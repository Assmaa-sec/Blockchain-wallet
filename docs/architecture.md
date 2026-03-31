# System Architecture

## Overview

The system is divided into six components that communicate over authenticated channels. The main design principle is that no single component should have access to the full private key or more information than it needs to do its job.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         External Boundary                           │
│                                                                     │
│   ┌──────────┐    HTTPS/mTLS     ┌────────────────────────────┐    │
│   │  Client  │ ─────────────────▶│       API Layer            │    │
│   └──────────┘                   │  (Flask REST, auth, rate   │    │
│                                  │   limit, input validation) │    │
│                                  └────────────┬───────────────┘    │
│                                               │                     │
│                            ┌──────────────────▼──────────────┐     │
│                            │         Wallet Core             │     │
│                            │  (Transaction, StateMachine,    │     │
│                            │   AuditLogger)                  │     │
│                            └──────┬───────────────┬──────────┘     │
│                                   │               │                 │
│                    ┌──────────────▼──┐   ┌────────▼────────────┐   │
│                    │  Signing Layer  │   │  Monitoring Layer   │   │
│                    │  (ThresholdECDSA│   │  (AnomalyDetector)  │   │
│                    │   PartialSig)   │   └─────────────────────┘   │
│                    └────────┬────────┘                             │
│                             │  (partial sig requests)              │
│            ┌────────────────▼────────────────────────────────┐    │
│            │               Admin Nodes (×5)                  │    │
│            │  ┌──────────────┐    ┌──────────────────────┐   │    │
│            │  │ AdminClient  │    │    TEE / SGX Enclave  │   │    │
│            │  │ (TLS client) │───▶│  (key share storage) │   │    │
│            │  └──────────────┘    └──────────────────────┘   │    │
│            └────────────────────────────────────────────────-┘    │
│                                                                     │
│            ┌────────────────────────────────────────────────┐      │
│            │             Crypto Primitives                  │      │
│            │  ┌───────┐  ┌──────────┐  ┌─────────────────┐ │      │
│            │  │  DKG  │  │ Shamir SS│  │    VSS (Feldman) │ │      │
│            │  └───────┘  └──────────┘  └─────────────────┘ │      │
│            └────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Components

### API Layer (`api/`)
The entry point for all requests. Handles token authentication, input validation, and delegates everything else to the wallet core. Every action is logged to the audit trail before returning a response.

### Wallet Core (`wallet/`)
Three main classes here. `Transaction` holds the data and current state. `TransactionStateMachine` controls which state transitions are allowed and rejects anything illegal. `AuditLogger` keeps an append-only hash-chained log of every event so nothing can be silently modified later.

The state flow is: `CREATED → AWAITING_APPROVALS → SIGNING → SIGNED`, with `FAILED` and `EXPIRED` as possible outcomes from the middle states.

### Signing Layer (`signing/`)
`ThresholdECDSA` coordinates the three-round MPC protocol. It collects nonce commitments, verifies them on reveal, then collects partial signatures and aggregates them. If anything goes wrong at any round, the session is aborted and all ephemeral state is cleared.

### Admin Nodes (`admin/`)
Each administrator runs an `AdminClient` that connects to the coordinator API and an `TEEInterface` that handles key storage. The TEE is simulated here but in a real deployment it would be an SGX enclave, meaning the key share never leaves protected memory even if the host OS is compromised.

### Crypto Primitives (`crypto/`)
The low-level building blocks. DKG runs the key generation ceremony, Shamir SS handles share splitting and reconstruction, and VSS lets participants verify they received a valid share without needing to trust the dealer.

### Monitoring (`monitoring/`)
Watches the audit log for suspicious patterns - approvals happening too fast, unusually large transactions, or repeated signing failures. Raises structured alerts that can be forwarded to external monitoring.

---

## Trust separation

The key property of this design is that no single layer holds the complete private key at any point.

| Layer | Secrets it holds |
|-------|-----------------|
| API Layer | Admin token (env var only) |
| Wallet Core | Nothing |
| Signing Layer | Per-session nonces (discarded after use) |
| Admin Node (TEE) | One key share (sealed in enclave) |
| Crypto Primitives | Nothing |

This means that compromising one component - even one admin node - is not enough to steal funds. An attacker would need to compromise at least `t` admin nodes simultaneously.

---

## Transaction flow

```
1.  Client            → POST /transactions/create
2.  API Layer         → validates, creates Transaction (CREATED)
3.  API Layer         → transitions to AWAITING_APPROVALS
4.  AuditLogger       → logs TRANSACTION_CREATED
5.  Admin Nodes (×3+) → review transaction via GET /transactions/{id}/status
6.  Admin Nodes (×3+) → POST /transactions/{id}/approve
7.  AuditLogger       → logs TRANSACTION_APPROVED for each
8.  AnomalyDetector   → checks for rapid approvals
9.  Client            → POST /transactions/{id}/sign
10. API Layer         → transitions to SIGNING
11. ThresholdECDSA    → Round 1: collect nonce commitments from 3 admins
12. ThresholdECDSA    → Round 2: reveal nonces, verify commitments, compute joint nonce
13. ThresholdECDSA    → Round 3: collect partial sigs, aggregate into final signature
14. API Layer         → transitions to SIGNED, stores signature
15. AuditLogger       → logs TRANSACTION_SIGNED
16. Client            → broadcasts signed transaction to the network
```

---

## API design notes

The API is stateless REST - each request carries the full auth token, no server-side sessions. This was chosen mainly to keep things simple; it also makes horizontal scaling straightforward if needed.

The `/sign` endpoint is synchronous, meaning it blocks until all three MPC rounds complete. This is fine for a small number of admins but would not scale well if signing latency becomes a concern. An async approach where the client polls `/status` would be better for production.

Transactions are stored in memory for this implementation. A real deployment would need a proper database with row-level locking to handle concurrent approval requests safely. The audit log would also need to be shipped to an external append-only store rather than kept in memory.
