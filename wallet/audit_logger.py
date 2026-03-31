import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List


class AuditLogger:
    GENESIS_HASH = "0" * 64

    def __init__(self):
        self._entries: List[Dict[str, Any]] = []

    def log_event(self, event_type: str, actor: str, details: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = datetime.now(timezone.utc).isoformat()
        previous_hash = self._entries[-1]["entry_hash"] if self._entries else self.GENESIS_HASH

        entry_data = json.dumps(
            {
                "timestamp": timestamp,
                "actor": actor,
                "event_type": event_type,
                "details": details,
            },
            sort_keys=True,
        )
        entry_hash = self._compute_hash(previous_hash + entry_data)

        entry = {
            "timestamp": timestamp,
            "actor": actor,
            "event_type": event_type,
            "details": details,
            "previous_hash": previous_hash,
            "entry_hash": entry_hash,
        }
        self._entries.append(entry)
        return entry

    def verify_chain(self) -> bool:
        expected_previous = self.GENESIS_HASH
        for entry in self._entries:
            if entry["previous_hash"] != expected_previous:
                return False

            entry_data = json.dumps(
                {
                    "timestamp": entry["timestamp"],
                    "actor": entry["actor"],
                    "event_type": entry["event_type"],
                    "details": entry["details"],
                },
                sort_keys=True,
            )
            expected_hash = self._compute_hash(expected_previous + entry_data)
            if entry["entry_hash"] != expected_hash:
                return False

            expected_previous = entry["entry_hash"]
        return True

    def export_logs(self) -> str:
        return json.dumps(self._entries, indent=2)

    def get_entries(self) -> List[Dict[str, Any]]:
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    @staticmethod
    def _compute_hash(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()
