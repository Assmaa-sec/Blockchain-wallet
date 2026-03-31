from datetime import datetime, timezone
from typing import Set, Tuple

from .transaction import Transaction, TransactionState

_ALLOWED_TRANSITIONS: Set[Tuple[TransactionState, TransactionState]] = {
    (TransactionState.CREATED, TransactionState.AWAITING_APPROVALS),
    (TransactionState.AWAITING_APPROVALS, TransactionState.SIGNING),
    (TransactionState.AWAITING_APPROVALS, TransactionState.EXPIRED),
    (TransactionState.AWAITING_APPROVALS, TransactionState.FAILED),
    (TransactionState.SIGNING, TransactionState.SIGNED),
    (TransactionState.SIGNING, TransactionState.FAILED),
}


class InvalidStateTransition(Exception):
    pass


class TransactionStateMachine:
    def transition(self, tx: Transaction, new_state: TransactionState) -> None:
        if tx.is_expired() and tx.status not in (
            TransactionState.SIGNED,
            TransactionState.FAILED,
            TransactionState.EXPIRED,
        ):
            tx.status = TransactionState.EXPIRED
            raise RuntimeError(
                f"Transaction {tx.id} has expired and cannot transition to {new_state.name}."
            )

        if not self.is_valid_transition(tx.status, new_state):
            raise InvalidStateTransition(
                f"Transition {tx.status.name} → {new_state.name} is not allowed."
            )

        tx.status = new_state

    def is_valid_transition(self, current: TransactionState, new: TransactionState) -> bool:
        return (current, new) in _ALLOWED_TRANSITIONS

    def expire_if_needed(self, tx: Transaction) -> bool:
        if tx.is_expired() and tx.status in (
            TransactionState.CREATED,
            TransactionState.AWAITING_APPROVALS,
        ):
            tx.status = TransactionState.EXPIRED
            return True
        return False
