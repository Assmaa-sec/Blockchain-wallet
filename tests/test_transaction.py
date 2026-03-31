from datetime import datetime, timedelta, timezone

import pytest

from wallet.transaction import Transaction, TransactionState
from wallet.state_machine import TransactionStateMachine, InvalidStateTransition


def make_tx(**kwargs) -> Transaction:
    defaults = dict(sender="0xAlice", recipient="0xBob", amount=100)
    defaults.update(kwargs)
    return Transaction(**defaults)


class TestValidStateTransitions:
    def test_created_to_awaiting(self):
        sm = TransactionStateMachine()
        tx = make_tx()
        sm.transition(tx, TransactionState.AWAITING_APPROVALS)
        assert tx.status == TransactionState.AWAITING_APPROVALS

    def test_awaiting_to_signing(self):
        sm = TransactionStateMachine()
        tx = make_tx()
        sm.transition(tx, TransactionState.AWAITING_APPROVALS)
        sm.transition(tx, TransactionState.SIGNING)
        assert tx.status == TransactionState.SIGNING

    def test_signing_to_signed(self):
        sm = TransactionStateMachine()
        tx = make_tx()
        sm.transition(tx, TransactionState.AWAITING_APPROVALS)
        sm.transition(tx, TransactionState.SIGNING)
        sm.transition(tx, TransactionState.SIGNED)
        assert tx.status == TransactionState.SIGNED

    def test_awaiting_to_failed(self):
        sm = TransactionStateMachine()
        tx = make_tx()
        sm.transition(tx, TransactionState.AWAITING_APPROVALS)
        sm.transition(tx, TransactionState.FAILED)
        assert tx.status == TransactionState.FAILED

    def test_signing_to_failed(self):
        sm = TransactionStateMachine()
        tx = make_tx()
        sm.transition(tx, TransactionState.AWAITING_APPROVALS)
        sm.transition(tx, TransactionState.SIGNING)
        sm.transition(tx, TransactionState.FAILED)
        assert tx.status == TransactionState.FAILED


class TestInvalidStateTransition:
    def test_created_to_signed_raises(self):
        sm = TransactionStateMachine()
        tx = make_tx()
        with pytest.raises(InvalidStateTransition):
            sm.transition(tx, TransactionState.SIGNED)

    def test_signed_to_any_raises(self):
        sm = TransactionStateMachine()
        tx = make_tx()
        sm.transition(tx, TransactionState.AWAITING_APPROVALS)
        sm.transition(tx, TransactionState.SIGNING)
        sm.transition(tx, TransactionState.SIGNED)
        for state in [
            TransactionState.CREATED,
            TransactionState.AWAITING_APPROVALS,
            TransactionState.SIGNING,
            TransactionState.FAILED,
        ]:
            with pytest.raises(InvalidStateTransition):
                sm.transition(tx, state)

    def test_failed_to_signing_raises(self):
        sm = TransactionStateMachine()
        tx = make_tx()
        sm.transition(tx, TransactionState.AWAITING_APPROVALS)
        sm.transition(tx, TransactionState.FAILED)
        with pytest.raises(InvalidStateTransition):
            sm.transition(tx, TransactionState.SIGNING)

    def test_same_admin_cannot_approve_twice(self):
        sm = TransactionStateMachine()
        tx = make_tx()
        sm.transition(tx, TransactionState.AWAITING_APPROVALS)
        tx.add_approval("admin1")
        with pytest.raises(ValueError):
            tx.add_approval("admin1")


class TestTransactionExpiry:
    def test_expired_transaction_is_detected(self):
        tx = make_tx(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        assert tx.is_expired()

    def test_non_expired_transaction(self):
        tx = make_tx(expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        assert not tx.is_expired()

    def test_expire_if_needed_sets_state(self):
        sm = TransactionStateMachine()
        tx = make_tx(expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        sm.transition(tx, TransactionState.AWAITING_APPROVALS)
        tx.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        expired = sm.expire_if_needed(tx)
        assert expired
        assert tx.status == TransactionState.EXPIRED

    def test_transition_raises_on_expired_tx(self):
        sm = TransactionStateMachine()
        tx = make_tx(expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        sm.transition(tx, TransactionState.AWAITING_APPROVALS)
        tx.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        with pytest.raises(RuntimeError, match="expired"):
            sm.transition(tx, TransactionState.SIGNING)

    def test_transaction_without_expiry_never_expires(self):
        tx = make_tx()
        assert not tx.is_expired()
