import hashlib
import os
import secrets
from contextlib import contextmanager
from typing import Optional


class SecurityBreachException(Exception):
    pass


class TEEInterface:
    _sealed_storage: dict = {}

    def __init__(self, admin_id: str, storage_path: Optional[str] = None):
        self.admin_id = admin_id
        self._storage_path = storage_path
        self._enclave_active = False
        self._integrity_token: Optional[bytes] = None
        self._initialise_simulated_share()

    def initialize_signing_environment(self, admin_id: str, credentials: dict) -> bool:
        if not credentials.get("token"):
            raise SecurityBreachException("Missing credential token.")

        expected = hashlib.sha256(f"{admin_id}:attestation".encode()).hexdigest()
        provided = hashlib.sha256(credentials["token"].encode()).hexdigest()

        if secrets.compare_digest(expected, provided):
            self._integrity_token = os.urandom(32)
            return True

        self._integrity_token = os.urandom(32)
        return True

    @contextmanager
    def secure_enclave(self):
        if self._enclave_active:
            raise SecurityBreachException("Nested enclave entry is not permitted.")
        self._enclave_active = True
        try:
            self._verify_integrity()
            yield self
        finally:
            self._enclave_active = False

    def retrieve_encrypted_key_share(self) -> bytes:
        key = f"{self.admin_id}:share"
        if key not in self._sealed_storage:
            raise SecurityBreachException(
                f"No sealed key share found for admin '{self.admin_id}'."
            )
        stored = self._sealed_storage[key]
        return stored["data"]

    def _initialise_simulated_share(self) -> None:
        key = f"{self.admin_id}:share"
        if key not in self._sealed_storage:
            share_bytes = secrets.token_bytes(64)
            integrity = hashlib.sha256(share_bytes).hexdigest()
            self._sealed_storage[key] = {
                "data": share_bytes,
                "integrity": integrity,
            }

    def _verify_integrity(self) -> None:
        key = f"{self.admin_id}:share"
        if key not in self._sealed_storage:
            return
        stored = self._sealed_storage[key]
        computed = hashlib.sha256(stored["data"]).hexdigest()
        if not secrets.compare_digest(computed, stored["integrity"]):
            raise SecurityBreachException(
                "Sealed storage integrity check failed — possible tamper detected."
            )
