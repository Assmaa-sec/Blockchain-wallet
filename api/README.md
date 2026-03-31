# api/

| File | What it does |
|------|-------------|
| `routes.py` | Flask app with all the endpoints and the auth decorator |

## Endpoints

| Method | Path | What it does |
|--------|------|-------------|
| POST | `/transactions/create` | Create a new transaction |
| POST | `/transactions/<id>/approve` | Submit an admin approval |
| POST | `/transactions/<id>/sign` | Trigger signing (needs 3+ approvals first) |
| GET | `/transactions/<id>/status` | Check transaction status |

## Auth

Every request needs:
```
Authorization: Bearer <WALLET_ADMIN_TOKEN>
```

Set `WALLET_ADMIN_TOKEN` as an environment variable before running.

## Running

```bash
export WALLET_ADMIN_TOKEN="your-token"
python -m api.routes
```
