from typing import List

_FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_BASE = 7


class VerifiableSecretSharing:
    def generate_commitments(self, polynomial_coefficients: List[int]) -> List[bytes]:
        return [
            ((coeff * _BASE) % _FIELD_PRIME).to_bytes(32, "big")
            for coeff in polynomial_coefficients
        ]

    def verify_share(self, share_value: int, commitments: List[bytes], party_index: int) -> bool:
        lhs = (share_value * _BASE) % _FIELD_PRIME

        rhs = 0
        for k, commitment_bytes in enumerate(commitments):
            c_k = int.from_bytes(commitment_bytes, "big")
            rhs = (rhs + c_k * pow(party_index, k, _FIELD_PRIME)) % _FIELD_PRIME

        return lhs == rhs
