# Blockchain Multi-Signature Wallet with Threshold Signatures and Secret Sharing


## Why this project?

Normal blockchain wallets use a single private key to sign transactions. The problem is that if that key is lost or stolen, the funds are gone. There's also no way to require multiple people to agree before a transaction goes through.

This project implements a 3-of-5 threshold wallet - meaning the wallet needs at least 3 out of 5 administrators to approve and sign a transaction before it can go through. The full private key is never assembled in one place at any point.

---

## How it works (overview)

```
Client  →  API  →  Wallet Core  →  Signing Layer  →  Admin Nodes (×5)
                                                           ↓
                                                    Crypto Primitives
                                                 (DKG, Shamir SS, VSS)
```

| Folder | What it does |
|--------|-------------|
| `api/` | Flask REST API, handles requests and authentication |
| `wallet/` | Transaction model, state machine, audit log |
| `signing/` | The 3-round threshold ECDSA signing protocol |
| `admin/` | Admin client + simulated SGX enclave for key storage |
| `crypto/` | DKG, Shamir secret sharing, VSS |
| `monitoring/` | Detects suspicious activity in the audit log |

---

## Cryptographic design

### Distributed Key Generation (DKG)
Each of the 5 admins generates a random polynomial and sends shares to the others. The final key share for each admin is the sum of all the shares they received. Nobody ever sees the full private key.

### Shamir Secret Sharing
The secret is split into shares using a degree-2 polynomial over the secp256k1 field. Any 3 shares can reconstruct the secret using Lagrange interpolation. Fewer than 3 shares reveal nothing.

### Verifiable Secret Sharing (VSS)
Each admin publishes commitments to their polynomial coefficients. This lets everyone verify that the share they received is valid, so a malicious admin can't hand out garbage shares undetected.

### Threshold ECDSA signing
Signing happens in 3 rounds:
1. Each signer commits to a random nonce
2. Nonces are revealed and verified, joint nonce is computed
3. Each signer produces a partial signature, coordinator combines them

---

## Security summary

| Threat | How it's handled |
|--------|-----------------|
| One admin gets compromised | One share can't sign anything, needs 2 more |
| Fewer than 3 admins collude | Mathematically can't produce a valid signature |
| Man-in-the-middle attack | mTLS between all components |
| Replay attack | Fresh random nonces every session + UUID in transaction hash |
| Audit log tampering | SHA-256 hash chain, any change breaks the chain |
| Key brute force | 2²⁵⁶ search space, shares stored in SGX sealed storage |

More detail in [docs/security_analysis.md](docs/security_analysis.md).

---

## Installation

Requires Python 3.11+

```bash
pip install -r requirements.txt
```

---

## Running the API

```bash
export WALLET_ADMIN_TOKEN="your-token-here"
python -m api.routes
```

Quick test with curl:

```bash
# Create a transaction
curl -X POST http://localhost:5000/transactions/create \
  -H "Authorization: Bearer $WALLET_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sender":"0xAlice","recipient":"0xBob","amount":1000,"actor":"admin1"}'

# Approve it (do this 3 times with different admin_id values)
curl -X POST http://localhost:5000/transactions/<tx_id>/approve \
  -H "Authorization: Bearer $WALLET_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"admin_id":"admin1"}'

# Sign once 3 approvals are in
curl -X POST http://localhost:5000/transactions/<tx_id>/sign \
  -H "Authorization: Bearer $WALLET_ADMIN_TOKEN"

# Check status
curl http://localhost:5000/transactions/<tx_id>/status \
  -H "Authorization: Bearer $WALLET_ADMIN_TOKEN"
```

---

## Running the tests

```bash
pytest tests/ -v
```

All 44 tests should pass.

---

## References

1. Shamir, A. (1979). How to share a secret. *Communications of the ACM*, 22(11), 612–613.
2. Feldman, P. (1987). A practical scheme for non-interactive verifiable secret sharing. *FOCS 1987*.
3. Gennaro, R., & Goldfeder, S. (2018). Fast multiparty threshold ECDSA with fast trustless setup. *CCS 2018*.
4. Canetti, R. et al. (2021). UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts. *CCS 2021*.
5. secp256k1 spec: https://en.bitcoin.it/wiki/Secp256k1
