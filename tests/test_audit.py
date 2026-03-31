import json

import pytest

from wallet.audit_logger import AuditLogger


class TestHashChainIntegrity:
    def test_empty_log_is_valid(self):
        assert AuditLogger().verify_chain()

    def test_single_entry_chain_is_valid(self):
        logger = AuditLogger()
        logger.log_event("TX_CREATED", actor="admin1", details={"tx_id": "abc"})
        assert logger.verify_chain()

    def test_multi_entry_chain_is_valid(self):
        logger = AuditLogger()
        for i in range(10):
            logger.log_event("EVENT", actor=f"actor_{i}", details={"seq": i})
        assert logger.verify_chain()

    def test_genesis_hash_of_first_entry(self):
        logger = AuditLogger()
        entry = logger.log_event("INIT", actor="system", details={})
        assert entry["previous_hash"] == AuditLogger.GENESIS_HASH


class TestTamperDetection:
    def test_modify_details_breaks_chain(self):
        logger = AuditLogger()
        logger.log_event("TX_CREATED", actor="admin1", details={"amount": 100})
        logger.log_event("TX_APPROVED", actor="admin2", details={"amount": 100})
        logger._entries[0]["details"]["amount"] = 999999
        assert not logger.verify_chain()

    def test_modify_actor_breaks_chain(self):
        logger = AuditLogger()
        logger.log_event("TX_SIGNED", actor="admin1", details={})
        logger._entries[0]["actor"] = "attacker"
        assert not logger.verify_chain()

    def test_delete_entry_breaks_chain(self):
        logger = AuditLogger()
        for i in range(5):
            logger.log_event("EVENT", actor="a", details={"i": i})
        del logger._entries[2]
        assert not logger.verify_chain()

    def test_reorder_entries_breaks_chain(self):
        logger = AuditLogger()
        for i in range(3):
            logger.log_event("EVENT", actor="a", details={"i": i})
        logger._entries[0], logger._entries[1] = logger._entries[1], logger._entries[0]
        assert not logger.verify_chain()


class TestLogExport:
    def test_export_returns_valid_json(self):
        logger = AuditLogger()
        logger.log_event("TX_CREATED", actor="admin1", details={"tx_id": "xyz"})
        logger.log_event("TX_APPROVED", actor="admin2", details={"tx_id": "xyz"})
        parsed = json.loads(logger.export_logs())
        assert isinstance(parsed, list)
        assert len(parsed) == 2

    def test_export_contains_required_fields(self):
        logger = AuditLogger()
        logger.log_event("TEST_EVENT", actor="tester", details={"key": "value"})
        entry = json.loads(logger.export_logs())[0]
        required_fields = {"timestamp", "actor", "event_type", "details", "previous_hash", "entry_hash"}
        assert required_fields.issubset(entry.keys())

    def test_export_reflects_all_entries(self):
        logger = AuditLogger()
        for i in range(7):
            logger.log_event("EVENT", actor="a", details={"i": i})
        assert len(json.loads(logger.export_logs())) == 7

    def test_get_entries_returns_copy(self):
        logger = AuditLogger()
        logger.log_event("EVENT", actor="a", details={})
        entries = logger.get_entries()
        entries.clear()
        assert len(logger) == 1
