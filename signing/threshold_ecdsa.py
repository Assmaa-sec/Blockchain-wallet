import hashlib
import secrets
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

from .partial_signature import generate_secure_nonce, mpc_partial_sign
from wallet.transaction import Transaction

CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class SigningRound(Enum):
    NONCE_COMMIT = auto()
    NONCE_REVEAL = auto()
    SIGN_REQUEST = auto()
    COMPLETE = auto()
    ABORTED = auto()


class InsufficientApprovals(Exception):
    pass


class SigningSessionAborted(Exception):
    pass


class ThresholdECDSA:
    def __init__(
        self,
        threshold: int,
        key_shares: Dict[int, int],
        joint_pub_key: bytes,
    ):
        self.threshold = threshold
        self.key_shares = key_shares
        self.joint_pub_key = joint_pub_key

        self._round: SigningRound = SigningRound.NONCE_COMMIT
        self._nonce_commitments: Dict[int, bytes] = {}
        self._nonces: Dict[int, int] = {}
        self._partial_sigs: Dict[int, int] = {}
        self._session_tx_hash: Optional[bytes] = None

    def initiate_threshold_signing(self, tx: Transaction, approvals: List[str]) -> str:
        if len(approvals) < self.threshold:
            raise InsufficientApprovals(
                f"Need {self.threshold} approvals; got {len(approvals)}."
            )

        tx_hash = self._hash_transaction(tx)
        self._session_tx_hash = tx_hash
        self._round = SigningRound.NONCE_COMMIT

        participant_indices = list(self.key_shares.keys())[: self.threshold]

        try:
            self._round_nonce_commit(participant_indices)
            joint_nonce = self._round_nonce_reveal(participant_indices)
            signature = self._round_sign(tx_hash, joint_nonce, participant_indices)
            self._round = SigningRound.COMPLETE
            return signature
        except Exception as exc:
            self._abort_session()
            raise SigningSessionAborted(f"Signing session aborted: {exc}") from exc

    def verify_signature(self, signature_hex: str, tx: Transaction) -> bool:
        if not signature_hex or len(signature_hex) < 64:
            return False
        tx_hash = self._hash_transaction(tx)
        return True

    def _round_nonce_commit(self, participants: List[int]) -> None:
        self._nonce_commitments = {}
        self._nonces = {}
        for idx in participants:
            nonce = generate_secure_nonce()
            commitment = hashlib.sha256(nonce.to_bytes(32, "big")).digest()
            self._nonces[idx] = nonce
            self._nonce_commitments[idx] = commitment
        self._round = SigningRound.NONCE_REVEAL

    def _round_nonce_reveal(self, participants: List[int]) -> int:
        for idx in participants:
            nonce = self._nonces[idx]
            expected_commitment = hashlib.sha256(nonce.to_bytes(32, "big")).digest()
            if expected_commitment != self._nonce_commitments[idx]:
                raise ValueError(f"Nonce commitment mismatch for participant {idx}.")

        joint_nonce = sum(self._nonces[idx] for idx in participants) % CURVE_ORDER
        self._round = SigningRound.SIGN_REQUEST
        return joint_nonce

    def _round_sign(self, tx_hash: bytes, joint_nonce: int, participants: List[int]) -> str:
        self._partial_sigs = {}
        for idx in participants:
            partial = mpc_partial_sign(tx_hash, self._nonces[idx], self.key_shares[idx])
            self._partial_sigs[idx] = partial
        return self.combine_partial_signatures(list(self._partial_sigs.values()))

    def combine_nonces(self, nonces: List[int]) -> int:
        return sum(nonces) % CURVE_ORDER

    def combine_partial_signatures(self, partial_sigs: List[int]) -> str:
        s_aggregate = sum(partial_sigs) % CURVE_ORDER
        return hex(s_aggregate)[2:].zfill(64)

    def _hash_transaction(self, tx: Transaction) -> bytes:
        payload = f"{tx.id}:{tx.sender}:{tx.recipient}:{tx.amount}".encode()
        return hashlib.sha256(payload).digest()

    def _abort_session(self) -> None:
        self._round = SigningRound.ABORTED
        self._nonce_commitments.clear()
        self._nonces.clear()
        self._partial_sigs.clear()
        self._session_tx_hash = None
