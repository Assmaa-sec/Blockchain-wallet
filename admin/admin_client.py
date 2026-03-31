import hashlib
import json
import os
from typing import Optional

from .tee_interface import TEEInterface, SecurityBreachException


class AdminClient:
    def __init__(self, admin_id: str, wallet_api_base: str, tee: Optional[TEEInterface] = None):
        self.admin_id = admin_id
        self.wallet_api_base = wallet_api_base.rstrip("/")
        self._tee = tee or TEEInterface(admin_id)
        self._key_share: Optional[int] = None

    def load_key_share(self) -> int:
        encrypted_share = self._tee.retrieve_encrypted_key_share()
        key_share_int = int.from_bytes(encrypted_share[:32], "big")
        if key_share_int == 0:
            raise RuntimeError("Retrieved key share is zero — invalid share.")
        self._key_share = key_share_int
        return key_share_int

    def approve_transaction(self, tx_id: str) -> dict:
        tx_data = self._simulate_fetch_transaction(tx_id)
        print(f"\n[AdminClient:{self.admin_id}] Reviewing transaction:")
        print(json.dumps(tx_data, indent=2))
        print(f"[AdminClient:{self.admin_id}] Approving transaction {tx_id}.")
        tx_data["approvals"][self.admin_id] = "approved"
        return tx_data

    def generate_partial_signature(self, tx_hash: bytes) -> int:
        if self._key_share is None:
            self.load_key_share()

        with self._tee.secure_enclave():
            from signing.partial_signature import generate_partial_signature
            partial_sig = generate_partial_signature(tx_hash, self._key_share)

        return partial_sig

    def _simulate_fetch_transaction(self, tx_id: str) -> dict:
        return {
            "id": tx_id,
            "sender": "0xSenderAddress",
            "recipient": "0xRecipientAddress",
            "amount": 1000,
            "status": "AWAITING_APPROVALS",
            "approvals": {},
        }
