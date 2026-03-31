import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class AnomalyDetector:
    DEFAULT_RAPID_APPROVAL_WINDOW_SECONDS = 60
    DEFAULT_RAPID_APPROVAL_COUNT = 3
    DEFAULT_FAILURE_THRESHOLD = 3

    def __init__(self):
        self._alerts: List[Dict[str, Any]] = []

    def detect_rapid_approvals(
        self,
        events: List[Dict[str, Any]],
        threshold_seconds: int = DEFAULT_RAPID_APPROVAL_WINDOW_SECONDS,
    ) -> bool:
        approval_events = [
            e for e in events if e.get("event_type") == "TRANSACTION_APPROVED"
        ]
        if len(approval_events) < self.DEFAULT_RAPID_APPROVAL_COUNT:
            return False

        timestamps = sorted(
            self._parse_timestamp(e["timestamp"]) for e in approval_events
        )

        for i in range(len(timestamps) - self.DEFAULT_RAPID_APPROVAL_COUNT + 1):
            window_start = timestamps[i]
            window_end = timestamps[i + self.DEFAULT_RAPID_APPROVAL_COUNT - 1]
            delta = (window_end - window_start).total_seconds()
            if delta <= threshold_seconds:
                self.raise_alert(
                    severity="HIGH",
                    message=(
                        f"Rapid approval detected: {self.DEFAULT_RAPID_APPROVAL_COUNT} "
                        f"approvals within {delta:.1f}s (threshold={threshold_seconds}s)."
                    ),
                )
                return True
        return False

    def detect_high_value_transaction(self, tx: Dict[str, Any], threshold_amount: int) -> bool:
        amount = tx.get("amount", 0)
        if amount > threshold_amount:
            self.raise_alert(
                severity="MEDIUM",
                message=(
                    f"High-value transaction detected: tx_id={tx.get('id')}, "
                    f"amount={amount} (threshold={threshold_amount})."
                ),
            )
            return True
        return False

    def detect_unusual_signing_failure(
        self,
        events: List[Dict[str, Any]],
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
    ) -> bool:
        failures = [e for e in events if e.get("event_type") == "SIGNING_FAILED"]
        if len(failures) >= failure_threshold:
            self.raise_alert(
                severity="HIGH",
                message=(
                    f"Repeated signing failures: {len(failures)} failures detected "
                    f"(threshold={failure_threshold})."
                ),
            )
            return True
        return False

    def raise_alert(self, severity: str, message: str) -> Dict[str, Any]:
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "message": message,
        }
        self._alerts.append(alert)
        print(f"[ALERT:{severity}] {message}")
        return alert

    def get_alerts(self) -> List[Dict[str, Any]]:
        return list(self._alerts)

    def export_alerts(self) -> str:
        return json.dumps(self._alerts, indent=2)

    @staticmethod
    def _parse_timestamp(ts: str) -> datetime:
        try:
            return datetime.fromisoformat(ts)
        except ValueError:
            return datetime.min.replace(tzinfo=timezone.utc)
