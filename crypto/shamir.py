import secrets
from typing import List, Tuple

FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class ShamirSecretSharing:
    def __init__(self, threshold: int, total_parties: int):
        if threshold < 2:
            raise ValueError("Threshold must be >= 2.")
        if total_parties < threshold:
            raise ValueError("total_parties must be >= threshold.")
        self.threshold = threshold
        self.total_parties = total_parties

    def split_secret(self, secret: int) -> Tuple[List[int], List[int]]:
        secret = secret % FIELD_PRIME
        coefficients = [secret] + [
            secrets.randbelow(FIELD_PRIME - 1) + 1
            for _ in range(self.threshold - 1)
        ]
        shares = [self._evaluate_polynomial(coefficients, i + 1) for i in range(self.total_parties)]
        return coefficients, shares

    def reconstruct_secret(self, shares: List[Tuple[int, int]]) -> int:
        if len(shares) < self.threshold:
            raise ValueError(
                f"Need at least {self.threshold} shares; got {len(shares)}."
            )
        return self._lagrange_interpolation(shares[:self.threshold])

    @staticmethod
    def _evaluate_polynomial(coefficients: List[int], x: int) -> int:
        result = 0
        for coeff in reversed(coefficients):
            result = (result * x + coeff) % FIELD_PRIME
        return result

    @staticmethod
    def _lagrange_interpolation(shares: List[Tuple[int, int]]) -> int:
        secret = 0
        for i, (x_i, y_i) in enumerate(shares):
            numerator = 1
            denominator = 1
            for j, (x_j, _) in enumerate(shares):
                if i == j:
                    continue
                numerator = (numerator * (-x_j)) % FIELD_PRIME
                denominator = (denominator * (x_i - x_j)) % FIELD_PRIME
            # Modular inverse via Fermat's little theorem (FIELD_PRIME is prime)
            lagrange_coeff = (numerator * pow(denominator, FIELD_PRIME - 2, FIELD_PRIME)) % FIELD_PRIME
            secret = (secret + y_i * lagrange_coeff) % FIELD_PRIME
        return secret
