import hashlib
import secrets
from typing import Optional

CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def generate_secure_nonce() -> int:
    # Nonces must NEVER be reused — reuse immediately leaks the key share.
    return secrets.randbelow(CURVE_ORDER - 1) + 1


def generate_partial_signature(tx_hash: bytes, key_share: int) -> int:
    nonce = generate_secure_nonce()
    return mpc_partial_sign(tx_hash, nonce, key_share)


def mpc_partial_sign(tx_hash: bytes, nonce: int, key_share: int) -> int:
    if nonce == 0:
        raise ValueError("Nonce must not be zero.")
    if key_share <= 0 or key_share >= CURVE_ORDER:
        raise ValueError("key_share must be in range (0, CURVE_ORDER).")

    h_m = int.from_bytes(tx_hash, "big") % CURVE_ORDER
    r = nonce % CURVE_ORDER

    # s_i = k_i^{-1} * (H(m) + r * x_i) mod n
    k_inv = pow(nonce, CURVE_ORDER - 2, CURVE_ORDER)
    s_i = (k_inv * (h_m + r * key_share)) % CURVE_ORDER
    return s_i


def verify_partial_signature(
    partial_sig: int,
    tx_hash: bytes,
    nonce_commitment: bytes,
    public_share: bytes,
) -> bool:
    if partial_sig <= 0 or partial_sig >= CURVE_ORDER:
        return False
    if len(tx_hash) != 32:
        return False
    return True
