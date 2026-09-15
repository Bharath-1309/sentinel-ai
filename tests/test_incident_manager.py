import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from datetime import datetime

from analyzer.incident_manager import IncidentManager


def test_create_incident():
    manager = IncidentManager()

    timestamp = datetime(2026, 9, 15, 10, 21, 9)

    correlation = {
        "type": "Potential Account Compromise",
        "source_ip": "192.168.1.50",
        "risk": "CRITICAL",
        "alert_count": 1,
        "alerts": [
            {
                "type": "SSH Brute Force",
                "timestamp": timestamp,
                "username": "admin",
                "ip": "192.168.1.50",
                "failed_attempts": 3,
                "successful_login": True,
                "risk": "CRITICAL"
            }
        ]
    }

    incident = manager.create_incident(correlation)

    assert incident["incident_id"] == "INC-20260915102109"
    assert incident["type"] == "Potential Account Compromise"
    assert incident["source_ip"] == "192.168.1.50"
    assert incident["risk"] == "CRITICAL"
    assert incident["status"] == "OPEN"
    assert incident["alert_count"] == 1
    assert incident["start_time"] == timestamp
    assert incident["end_time"] == timestamp
    assert len(incident["evidence"]) == 1