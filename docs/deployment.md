# Deployment

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Production Environment                    │
│                                                             │
│  ┌──────────────┐     ┌──────────────┐     ┌────────────┐  │
│  │  Load        │────▶│  API Server  │────▶│  Database  │  │
│  │  Balancer    │     │  (Flask/     │     │ (Postgres) │  │
│  │  (TLS term)  │     │   Gunicorn)  │     └────────────┘  │
│  └──────────────┘     └──────┬───────┘                     │
│                              │                              │
│          ┌───────────────────┼──────────────────────┐       │
│          │                   │                      │       │
│  ┌───────▼────┐    ┌────────▼────┐    ┌────────────▼───┐   │
│  │ Admin Node │    │ Admin Node  │    │  Admin Node    │   │
│  │    #1      │    │     #2      │    │      #3        │   │
│  │  (SGX TEE) │    │  (SGX TEE)  │    │   (SGX TEE)    │   │
│  └────────────┘    └─────────────┘    └────────────────┘   │
│                                                             │
│  ┌────────────┐    ┌─────────────┐                         │
│  │ Admin Node │    │ Admin Node  │                         │
│  │    #4      │    │     #5      │  (cold-standby nodes)   │
│  │  (SGX TEE) │    │  (SGX TEE)  │                         │
│  └────────────┘    └─────────────┘                         │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │               Monitoring & Audit                     │  │
│  │  (AnomalyDetector → SIEM → PagerDuty alerting)       │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Minimum requirements

| Component | Spec |
|-----------|------|
| API Server | 2x vCPU, 4 GB RAM, TLS certificate |
| Admin Node | SGX-capable CPU (Ice Lake or newer), 8 GB RAM |
| Database | PostgreSQL 15+ with WAL archiving |
| Network | mTLS between all components |
| Audit log | External append-only ledger |

---

## DKG Ceremony

The key generation ceremony only needs to happen once, at setup. All five administrators need to be present (or connected). This is the most sensitive step in the whole process - if it goes wrong, the wallet is compromised from day one.

### Before you start

- [ ] Five SGX-capable machines set up with verified enclave builds
- [ ] Each machine has a certificate proving its identity
- [ ] All five nodes can reach the coordinator
- [ ] The ceremony is being recorded for audit purposes
- [ ] Security officer is present

### Steps

1. **Attestation** - Each node does SGX remote attestation. The coordinator checks the `MRENCLAVE` value for every node before proceeding. Any node that fails attestation is excluded.

2. **Polynomial generation** - Each node generates a random degree-(t-1) polynomial over the secp256k1 field:
   ```
   f_i(x) = a_{i,0} + a_{i,1}·x + … + a_{i,t-1}·x^{t-1}  mod n
   ```

3. **VSS commitments** - Each node publishes `C_{i,k} = g^{a_{i,k}}` for all their coefficients. This lets other nodes verify the shares they receive.

4. **Share exchange** - Each node i sends `f_i(j)` to node j, encrypted to that node's enclave key.

5. **Verification** - Each node verifies every share it received against the published commitments. If any share does not match, the ceremony is aborted and that node is flagged.

6. **Aggregation** - Each node computes its final key share:
   ```
   x_j = sum_i( f_i(j) )  mod n
   ```

7. **Public key** - Each node computes `X_j = x_j·G` and broadcasts it. The joint public key is `X = sum_j(X_j)`.

8. **Sealing** - Each node seals `x_j` into SGX sealed storage bound to its enclave identity.

9. **Test run** - Do a test signing session on a dummy transaction to confirm everything is consistent.

10. **Record** - Record the joint public key and ceremony transcript. Do not store any private share material outside the enclaves.

---

## Key Share Backup and Recovery

### Backup

Each key share `x_j` is split into three backup fragments using 2-of-3 Shamir:

- Fragment 1 - stored in an HSM in a bank vault
- Fragment 2 - printed as a QR code in a tamper-evident envelope at a separate location
- Fragment 3 - encrypted with the admin's passphrase and stored in cold cloud storage

Recovering the share requires any two of the three fragments plus the admin's credentials.

### Recovery steps

1. Collect at least two backup fragments
2. Reconstruct `x_j` using 2-of-3 Shamir reconstruction
3. Set up a new SGX-capable machine
4. Attest the new enclave
5. Load `x_j` into sealed storage inside the enclave
6. Run a test signing session to confirm the share works
7. Securely delete all temporary copies of `x_j` outside the enclave
8. Log the recovery event in the audit trail with witness attestation

### Key rotation

Rotation should happen if:
- Any node is compromised or suspected to be
- Annually as scheduled maintenance
- An administrator leaves or changes roles

Rotation requires a full new DKG ceremony. Mark the old public key as inactive and complete or cancel any pending transactions under it before switching over.

---

## Monitoring

### Metrics to watch

| Metric | Alert threshold |
|--------|----------------|
| Signing session latency | > 30s |
| Signing failure rate | > 1 per hour |
| Audit log chain integrity | Any failure |
| Admin node connectivity | < 3 of 5 online |
| Rapid approvals | 3+ in under 60s |
| High-value transaction | Configurable |

### Routine tasks

- **Weekly** - verify audit log chain, export and archive
- **Monthly** - review alert history, tune thresholds if needed
- **Quarterly** - run a test DKG on staging
- **Annually** - full key rotation, external security audit

### If something goes wrong

1. **Detect** - alert from AnomalyDetector or SIEM
2. **Isolate** - cut off the affected admin node's API access
3. **Assess** - check the audit log for anything unauthorized
4. **Contain** - if a share is suspected leaked, start key rotation immediately
5. **Recover** - restore from backup using the procedure above
6. **Post-mortem** - document what happened and update the threat model
