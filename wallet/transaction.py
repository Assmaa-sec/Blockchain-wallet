import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Dict, List, Optional


class TransactionState(Enum):
    CREATED = auto()
    AWAITING_APPROVALS = auto()
    SIGNING = auto()
    SIGNED = auto()
    FAILED = auto()
    EXPIRED = auto()


@dataclass
class Transaction:
    sender: str
    recipient: str
    amount: int

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: TransactionState = TransactionState.CREATED
    approvals: Dict[str, datetime] = field(default_factory=dict)
    signature: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None

    def validate(self) -> None:
        if not self.sender:
            raise ValueError("sender must not be empty.")
        if not self.recipient:
            raise ValueError("recipient must not be empty.")
        if self.amount <= 0:
            raise ValueError("amount must be a positive integer.")
        if self.sender == self.recipient:
            raise ValueError("sender and recipient must be different addresses.")

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def add_approval(self, admin_id: str) -> None:
        if self.status != TransactionState.AWAITING_APPROVALS:
            raise RuntimeError(
                f"Cannot add approval in state {self.status.name}."
            )
        if admin_id in self.approvals:
            raise ValueError(f"Admin '{admin_id}' has already approved this transaction.")
        self.approvals[admin_id] = datetime.now(timezone.utc)

    def approval_count(self) -> int:
        return len(self.approvals)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "status": self.status.name,
            "approvals": {k: v.isoformat() for k, v in self.approvals.items()},
            "signature": self.signature,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }
