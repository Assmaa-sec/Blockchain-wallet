# signing/

Handles the threshold ECDSA signing protocol.

| File | What it does |
|------|-------------|
| `threshold_ecdsa.py` | Coordinates the 3-round MPC signing session |
| `partial_signature.py` | Each signer uses this to compute their partial signature |

## The 3 rounds

1. **NONCE_COMMIT** - each signer picks a random nonce and sends a hash of it
2. **NONCE_REVEAL** - signers reveal their nonces, coordinator checks the hashes match and computes the joint nonce
3. **SIGN_REQUEST** - each signer computes `s_i = k_i^{-1} * (H(m) + r * x_i) mod n`, coordinator sums them up

Important: nonces must never be reused. Reusing a nonce across two different signing sessions leaks the key share.
