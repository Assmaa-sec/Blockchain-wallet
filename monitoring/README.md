# monitoring/

| File | What it does |
|------|-------------|
| `anomaly_detector.py` | Scans audit log events and raises alerts on suspicious patterns |

## Rules

- **Rapid approvals** - 3 or more approvals within 60 seconds triggers a HIGH alert
- **High-value transaction** - amount over a configurable limit triggers a MEDIUM alert
- **Repeated signing failures** - 3 or more failures in a row triggers a HIGH alert

Alerts are printed to stdout and stored in `_alerts`. In production you'd forward them to something like Splunk or PagerDuty.
