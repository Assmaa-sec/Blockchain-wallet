# wallet/

Core wallet logic.

| File | What it does |
|------|-------------|
| `transaction.py` | The `Transaction` dataclass and `TransactionState` enum |
| `state_machine.py` | Controls which state transitions are allowed |
| `audit_logger.py` | Append-only log where each entry is chained to the previous one |

## Transaction states

```
CREATED → AWAITING_APPROVALS → SIGNING → SIGNED
                             ↘ FAILED
                             ↘ EXPIRED
```

## Audit log entry format

```json
{
  "timestamp": "2026-03-31T10:00:00+00:00",
  "actor": "admin1",
  "event_type": "TRANSACTION_APPROVED",
  "details": { "tx_id": "...", "approval_count": 2 },
  "previous_hash": "...",
  "entry_hash": "sha256(previous_hash + this entry)"
}
```

Each entry's hash covers the previous one, so tampering with any entry breaks the rest of the chain.
