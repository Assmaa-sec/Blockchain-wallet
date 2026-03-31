import hashlib
import pytest

from signing.threshold_ecdsa import ThresholdECDSA, InsufficientApprovals, SigningSessionAborted
from signing.partial_signature import (
    generate_secure_nonce,
    mpc_partial_sign,
    verify_partial_signature,
    CURVE_ORDER,
)
from wallet.transaction import Transaction

THRESHOLD = 3
TOTAL = 5
KEY_SHARES = {1: 11111, 2: 22222, 3: 33333, 4: 44444, 5: 55555}
JOINT_PUB = b"\x04" + b"\xab" * 64


def make_engine() -> ThresholdECDSA:
    return ThresholdECDSA(THRESHOLD, KEY_SHARES, JOINT_PUB)


def make_tx() -> Transaction:
    return Transaction(sender="0xAlice", recipient="0xBob", amount=500)


class TestInsufficientApprovals:
    def test_insufficient_approvals_raises(self):
        engine = make_engine()
        tx = make_tx()
        with pytest.raises(InsufficientApprovals):
            engine.initiate_threshold_signing(tx, approvals=["admin1", "admin2"])

    def test_zero_approvals_raises(self):
        engine = make_engine()
        tx = make_tx()
        with pytest.raises(InsufficientApprovals):
            engine.initiate_threshold_signing(tx, approvals=[])


class TestPartialSignatureAggregation:
    def test_partial_signature_aggregation(self):
        engine = make_engine()
        result = engine.combine_partial_signatures([12345, 67890, 11111])
        assert isinstance(result, str)
        assert len(result) == 64

    def test_aggregate_matches_sum_mod_n(self):
        engine = make_engine()
        partial_sigs = [100, 200, 300]
        expected = hex(sum(partial_sigs) % CURVE_ORDER)[2:].zfill(64)
        assert engine.combine_partial_signatures(partial_sigs) == expected

    def test_full_signing_session_returns_hex(self):
        engine = make_engine()
        tx = make_tx()
        sig = engine.initiate_threshold_signing(tx, approvals=["admin1", "admin2", "admin3"])
        assert isinstance(sig, str)
        assert len(sig) == 64


class TestInvalidPartialSignature:
    def test_zero_nonce_raises(self):
        tx_hash = hashlib.sha256(b"test").digest()
        with pytest.raises(ValueError, match="Nonce must not be zero"):
            mpc_partial_sign(tx_hash, nonce=0, key_share=12345)

    def test_invalid_key_share_raises(self):
        tx_hash = hashlib.sha256(b"test").digest()
        with pytest.raises(ValueError):
            mpc_partial_sign(tx_hash, nonce=1, key_share=0)

    def test_verify_partial_signature_bad_range(self):
        tx_hash = hashlib.sha256(b"test").digest()
        assert not verify_partial_signature(
            partial_sig=0,
            tx_hash=tx_hash,
            nonce_commitment=b"\x00" * 32,
            public_share=b"\x04" + b"\x00" * 64,
        )


class TestSessionAbortOnFailure:
    def test_session_abort_on_signer_dropout(self, monkeypatch):
        engine = make_engine()
        tx = make_tx()

        def _bad_reveal(participants):
            raise ValueError("Participant 2 dropped out.")

        monkeypatch.setattr(engine, "_round_nonce_reveal", _bad_reveal)

        with pytest.raises(SigningSessionAborted):
            engine.initiate_threshold_signing(tx, approvals=["a1", "a2", "a3"])

    def test_session_state_is_aborted_after_failure(self, monkeypatch):
        from signing.threshold_ecdsa import SigningRound

        engine = make_engine()
        tx = make_tx()

        monkeypatch.setattr(
            engine, "_round_nonce_commit", lambda p: (_ for _ in ()).throw(RuntimeError("fail"))
        )

        with pytest.raises(SigningSessionAborted):
            engine.initiate_threshold_signing(tx, approvals=["a1", "a2", "a3"])

        assert engine._round == SigningRound.ABORTED
