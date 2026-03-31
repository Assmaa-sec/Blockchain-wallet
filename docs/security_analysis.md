# Security Analysis

## Threat Model

The main assets we are trying to protect are:
- The wallet private key (which is never fully reconstructed anywhere)
- The key shares held by each admin
- The integrity of the audit log
- The validity of transactions that get broadcast to the network

The assumed adversary can passively sniff network traffic, attempt active MITM attacks, and in the worst case has fully compromised up to `t-1` admin machines. The threshold model means that `t-1` compromised nodes still cannot produce a valid signature.

---

## Attack Scenarios

### 1. Single admin node compromise

An attacker fully compromises one admin machine and reads the key share from memory or storage.

With SGX sealing, the host OS cannot access sealed storage even with root privileges, so getting the share requires breaking the enclave. But even if they do get the share, they still need `t-1 = 2` more shares from other independent nodes to actually sign anything. This is the core security guarantee of the threshold scheme.

If a node is suspected compromised, the response is to trigger a new DKG ceremony and rotate all key shares.

---

### 2. Collusion below threshold

Two out of five admins decide to collude and try to authorize a transaction without the others.

Two partial signatures are not enough to produce a valid aggregate ECDSA signature - the math simply does not work out with fewer than `t` contributions. So this attack fails cryptographically regardless of how the admins coordinate.

The audit log also records all approvals with timestamps and actor IDs, so any collusion attempt is visible after the fact.

---

### 3. Collusion at threshold

Three admins (exactly `t`) collude to sign an unauthorized transaction.

This is harder to prevent purely at the cryptographic level since `t` shares are by definition sufficient to sign. The main defenses here are organizational rather than technical - separating admin roles across different departments (engineering, finance, legal, etc.) makes it much harder to coordinate this kind of attack. The 3-of-5 threshold was chosen assuming at most two insiders could be compromised or coerced at once.

Post-incident, the audit log provides a full forensic trail pointing to exactly which three admins approved the transaction.

For higher-value wallets, increasing to 4-of-7 would raise the collusion bar significantly.

---

### 4. Man-in-the-middle

An attacker intercepts traffic between the API and an admin node and tries to modify or replay approval messages.

All communication uses mutual TLS - both sides authenticate with certificates, so an attacker without a valid cert cannot impersonate either party. Even if a message is intercepted and modified, the admin node verifies the transaction hash before signing, and any modification would produce a different hash, making the partial signature invalid.

---

### 5. Replay attack

An attacker captures partial signatures from a completed signing session and tries to replay them for a different transaction.

This does not work because each signing session generates fresh random nonces, and the transaction hash includes the UUID, sender, recipient, and amount. Replaying old partial signatures against a new transaction hash will produce an invalid aggregate. The state machine also rejects a second signing attempt on a transaction that is already in the SIGNED state.

---

### 6. Denial of service

An attacker floods the API with requests to exhaust resources, or takes down enough admin nodes to prevent quorum.

Rate limiting on the API limits the damage from request floods. The `expires_at` field on transactions means stalled ones automatically move to EXPIRED rather than accumulating indefinitely. Admin nodes are assumed to be on separate isolated infrastructure, so taking all five down simultaneously would require significant access.

---

### 7. Audit log tampering

Someone - including a compromised admin - tries to modify past log entries to hide a fraudulent transaction.

Every log entry's hash covers the content of that entry plus the hash of the previous entry, so modifying any entry invalidates every entry that comes after it. `verify_chain()` will catch this. In a real deployment the log should also be replicated in real time to an external append-only store (like Amazon QLDB or a Merkle log service) that the wallet operator does not control.

---

### 8. Signer dropout during protocol

One or more admins go offline mid-signing, leaving the session incomplete.

The coordinator detects this when a round times out or a participant sends malformed data. `_abort_session()` clears all ephemeral nonces and partial signatures immediately. The transaction moves to FAILED and a new one has to be created. This is a liveness failure rather than a security failure - no key material is leaked.

---

### 9. Key share brute force

An attacker gets hold of one ciphertext key share and tries to brute force the value.

Key shares are integers in the secp256k1 scalar field, which has roughly 2^256 elements. This is not brute-forceable with any foreseeable hardware. On top of that, the ciphertext is bound to the SGX enclave identity so it cannot even be decrypted outside that specific enclave.

---

## Summary

| Property | How it's achieved |
|----------|------------------|
| Key confidentiality | DKG + TEE sealed storage |
| Signing authorization | 3-of-5 threshold approval |
| Non-repudiation | Hash-chained audit log |
| Tamper detection | SHA-256 chain + external log replication |
| Replay prevention | Per-session nonces + UUID-bound transaction hash |
| Communication integrity | mTLS |
| Insider threat resistance | Threshold + organizational separation |
| DoS resilience | Rate limiting + transaction expiry |
