# admin/

The admin-side components - one instance per administrator.

| File | What it does |
|------|-------------|
| `admin_client.py` | Fetches transactions, submits approvals, triggers partial signing |
| `tee_interface.py` | Simulated SGX enclave that stores and protects the key share |

The TEE (Trusted Execution Environment) is simulated here using an in-memory dict with SHA-256 integrity checks. In a real deployment this would be Intel SGX or something like Azure Confidential Computing, where the key share never leaves protected memory.

The `secure_enclave()` context manager is the boundary - anything that touches the key share should happen inside it.
