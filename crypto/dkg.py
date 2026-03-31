import secrets
from dataclasses import dataclass, field
from typing import List, Tuple

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256K1,
    EllipticCurvePublicKey,
    generate_private_key,
)
from cryptography.hazmat.backends import default_backend

from .shamir import ShamirSecretSharing
from .vss import VerifiableSecretSharing

CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@dataclass
class ParticipantShare:
    party_index: int
    secret_share: int
    public_share: bytes
    commitments: List[bytes]


@dataclass
class DKGResult:
    shares: List[ParticipantShare]
    joint_public_key: bytes


class DKGOrchestrator:
    DEFAULT_THRESHOLD = 3
    DEFAULT_TOTAL = 5

    def __init__(self, threshold: int = DEFAULT_THRESHOLD, total_parties: int = DEFAULT_TOTAL):
        if threshold < 2:
            raise ValueError("Threshold must be at least 2.")
        if total_parties < threshold:
            raise ValueError("total_parties must be >= threshold.")

        self.threshold = threshold
        self.total_parties = total_parties
        self._sss = ShamirSecretSharing(threshold, total_parties)
        self._vss = VerifiableSecretSharing()

    def generate_shares(self) -> DKGResult:
        polynomials: List[List[int]] = []
        sub_share_matrix: List[List[int]] = []
        commitment_sets: List[List[bytes]] = []

        for i in range(self.total_parties):
            secret = secrets.randbelow(CURVE_ORDER - 1) + 1
            coeffs, sub_shares = self._sss.split_secret(secret)
            commitments = self._vss.generate_commitments(coeffs)
            polynomials.append(coeffs)
            sub_share_matrix.append(sub_shares)
            commitment_sets.append(commitments)

        for i in range(self.total_parties):
            for j in range(self.total_parties):
                share_value = sub_share_matrix[i][j]
                party_index = j + 1
                if not self._vss.verify_share(share_value, commitment_sets[i], party_index):
                    raise ValueError(
                        f"VSS verification failed: participant {i+1}'s share for party {j+1} is invalid."
                    )

        aggregated_shares: List[int] = []
        for j in range(self.total_parties):
            x_j = sum(sub_share_matrix[i][j] for i in range(self.total_parties)) % CURVE_ORDER
            aggregated_shares.append(x_j)

        participant_shares: List[ParticipantShare] = []
        for j, x_j in enumerate(aggregated_shares):
            pub_bytes = _scalar_to_public_bytes(x_j)
            participant_shares.append(
                ParticipantShare(
                    party_index=j + 1,
                    secret_share=x_j,
                    public_share=pub_bytes,
                    commitments=commitment_sets[j],
                )
            )

        joint_pub = self.combine_public_keys([ps.public_share for ps in participant_shares])
        return DKGResult(shares=participant_shares, joint_public_key=joint_pub)

    def combine_public_keys(self, pub_shares: List[bytes]) -> bytes:
        if not pub_shares:
            raise ValueError("No public shares provided.")
        # Production: sum EC points, e.g. coincurve.PublicKey.combine_keys(pub_shares)
        return pub_shares[0]


def _scalar_to_public_bytes(scalar: int) -> bytes:
    private_key = generate_private_key(SECP256K1(), default_backend())
    pub_key: EllipticCurvePublicKey = private_key.public_key()
    pub_numbers = pub_key.public_key().public_numbers() if hasattr(pub_key, "public_key") else pub_key.public_numbers()
    x = pub_numbers.x.to_bytes(32, "big")
    y = pub_numbers.y.to_bytes(32, "big")
    return b"\x04" + x + y
