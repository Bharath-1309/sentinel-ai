from datetime import datetime

import analyzer.database as database


def test_initialize_database(tmp_path, monkeypatch):

    db_path = tmp_path / "test.db"

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        db_path
    )

    database.initialize_database()

    connection = database.get_connection()

    columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(incidents)"
        ).fetchall()
    }

    connection.close()

    assert "incidents" in columns or len(columns) > 0

    assert "mitre_techniques" in columns
    assert "evidence" in columns
    assert "ai_investigation" in columns
    assert "response_playbook" in columns


def test_save_and_get_incident(tmp_path, monkeypatch):

    db_path = tmp_path / "test.db"

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        db_path
    )

    database.initialize_database()

    timestamp = datetime(2026, 9, 17, 14, 0, 3)

    incident = {
        "incident_id": "INC-TEST-001",
        "type": "Credential Theft Activity",
        "source_ip": "192.168.1.80",
        "risk": "CRITICAL",
        "risk_score": 80,
        "status": "OPEN",
        "alert_count": 1,
        "start_time": timestamp,
        "end_time": timestamp,
        "mitre_techniques": [
            {
                "technique_id": "T1003",
                "technique": "OS Credential Dumping",
                "tactic": "Credential Access"
            }
        ],
        "evidence": [
            {
                "type": "Credential Dumping",
                "ip": "192.168.1.80",
                "risk": "CRITICAL"
            }
        ],
        "ai_investigation": {
            "investigation_status": "UNAVAILABLE",
            "analysis": "Gemini quota exceeded."
        },
        "response_playbook": {
            "severity": "CRITICAL",
            "actions": [
                "Isolate the affected endpoint"
            ]
        }
    }

    database.save_incident(incident)

    incidents = database.get_incidents()

    assert len(incidents) == 1

    saved = incidents[0]

    assert saved["incident_id"] == "INC-TEST-001"
    assert saved["incident_type"] == "Credential Theft Activity"
    assert saved["risk_score"] == 80

    assert saved["mitre_techniques"][0]["technique_id"] == "T1003"

    assert saved["evidence"][0]["type"] == "Credential Dumping"

    assert (
        saved["ai_investigation"]["investigation_status"]
        == "UNAVAILABLE"
    )

    assert (
        saved["response_playbook"]["severity"]
        == "CRITICAL"
    )

    assert (
        saved["response_playbook"]["actions"][0]
        == "Isolate the affected endpoint"
    )