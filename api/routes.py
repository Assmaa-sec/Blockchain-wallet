import hashlib
import os
import secrets
from functools import wraps
from typing import Callable

from flask import Flask, jsonify, request, abort

from wallet.transaction import Transaction, TransactionState
from wallet.state_machine import TransactionStateMachine, InvalidStateTransition
from wallet.audit_logger import AuditLogger
from signing.threshold_ecdsa import ThresholdECDSA, InsufficientApprovals, SigningSessionAborted

_transactions: dict = {}
_audit_logger = AuditLogger()
_state_machine = TransactionStateMachine()

_ADMIN_TOKEN = os.environ.get("WALLET_ADMIN_TOKEN", secrets.token_hex(32))

_THRESHOLD = 3
_KEY_SHARES: dict = {1: 111, 2: 222, 3: 333, 4: 444, 5: 555}
_JOINT_PUB_KEY = b"\x04" + b"\x00" * 64
_signing_engine = ThresholdECDSA(_THRESHOLD, _KEY_SHARES, _JOINT_PUB_KEY)


def create_app() -> Flask:
    app = Flask(__name__)

    def authenticate(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                abort(401, description="Missing or malformed Authorization header.")
            token = auth_header[len("Bearer "):]
            if not secrets.compare_digest(
                hashlib.sha256(token.encode()).digest(),
                hashlib.sha256(_ADMIN_TOKEN.encode()).digest(),
            ):
                _audit_logger.log_event(
                    "AUTH_FAILURE",
                    actor="unknown",
                    details={"remote_addr": request.remote_addr},
                )
                abort(403, description="Invalid admin token.")
            return f(*args, **kwargs)
        return decorated

    @app.post("/transactions/create")
    @authenticate
    def create_transaction():
        data = request.get_json(force=True)
        try:
            tx = Transaction(
                sender=data["sender"],
                recipient=data["recipient"],
                amount=int(data["amount"]),
            )
            tx.validate()
        except (KeyError, ValueError) as exc:
            abort(400, description=str(exc))

        _state_machine.transition(tx, TransactionState.AWAITING_APPROVALS)
        _transactions[tx.id] = tx

        _audit_logger.log_event(
            "TRANSACTION_CREATED",
            actor=data.get("actor", "api"),
            details=tx.to_dict(),
        )
        return jsonify(tx.to_dict()), 201

    @app.post("/transactions/<tx_id>/approve")
    @authenticate
    def approve_transaction(tx_id: str):
        tx = _get_tx_or_404(tx_id)
        data = request.get_json(force=True) or {}
        admin_id = data.get("admin_id", "unknown")

        try:
            tx.add_approval(admin_id)
        except (RuntimeError, ValueError) as exc:
            abort(400, description=str(exc))

        _audit_logger.log_event(
            "TRANSACTION_APPROVED",
            actor=admin_id,
            details={"tx_id": tx_id, "approval_count": tx.approval_count()},
        )
        return jsonify(tx.to_dict()), 200

    @app.post("/transactions/<tx_id>/sign")
    @authenticate
    def sign_transaction(tx_id: str):
        tx = _get_tx_or_404(tx_id)

        try:
            _state_machine.transition(tx, TransactionState.SIGNING)
            approvals = list(tx.approvals.keys())
            signature = _signing_engine.initiate_threshold_signing(tx, approvals)
            tx.signature = signature
            _state_machine.transition(tx, TransactionState.SIGNED)
        except InsufficientApprovals as exc:
            _state_machine.transition(tx, TransactionState.FAILED)
            _audit_logger.log_event(
                "SIGNING_FAILED",
                actor="system",
                details={"tx_id": tx_id, "reason": str(exc)},
            )
            abort(400, description=str(exc))
        except (SigningSessionAborted, InvalidStateTransition) as exc:
            _state_machine.transition(tx, TransactionState.FAILED)
            _audit_logger.log_event(
                "SIGNING_FAILED",
                actor="system",
                details={"tx_id": tx_id, "reason": str(exc)},
            )
            abort(500, description=str(exc))

        _audit_logger.log_event(
            "TRANSACTION_SIGNED",
            actor="system",
            details={"tx_id": tx_id, "signature": signature},
        )
        return jsonify(tx.to_dict()), 200

    @app.get("/transactions/<tx_id>/status")
    @authenticate
    def get_transaction_status(tx_id: str):
        tx = _get_tx_or_404(tx_id)
        _state_machine.expire_if_needed(tx)
        return jsonify(tx.to_dict()), 200

    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(500)
    def handle_error(exc):
        return jsonify({"error": exc.description}), exc.code

    return app


def _get_tx_or_404(tx_id: str) -> Transaction:
    tx = _transactions.get(tx_id)
    if tx is None:
        abort(404, description=f"Transaction '{tx_id}' not found.")
    return tx


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=False)
