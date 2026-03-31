# crypto/

This folder contains the core cryptographic building blocks.

| File | What it does |
|------|-------------|
| `dkg.py` | Runs the distributed key generation ceremony (3-of-5 setup) |
| `shamir.py` | Splits and reconstructs secrets using Shamir's scheme |
| `vss.py` | Verifiable secret sharing - lets participants check their shares are valid |

All arithmetic is done modulo the secp256k1 curve order.

The DKG runs the full ceremony locally (simulated). In a real deployment each admin would run their part independently on separate machines.

The VSS uses additive commitments over the secp256k1 field. A proper production version would use Pedersen commitments on the EC curve.
