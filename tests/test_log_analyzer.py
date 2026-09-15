import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.log_analyzer import analyze_logs
from analyzer.detection_engine import DetectionEngine


def test_ssh_brute_force_detection():
    result = analyze_logs()
    alerts = result["alerts"]

    assert len(alerts) == 2

    assert alerts[0]["timestamp"].strftime("%b %d %H:%M:%S") == "Sep 15 10:21:09"
    assert alerts[1]["timestamp"].strftime("%b %d %H:%M:%S") == "Sep 15 11:05:27"

    assert alerts[0]["type"] == "SSH Brute Force"
    assert alerts[0]["risk"] == "CRITICAL"

    assert alerts[1]["type"] == "SSH Brute Force"
    assert alerts[1]["risk"] == "MEDIUM"

def test_suspicious_root_login():
    analyze_logs()

def test_brute_force_time_window():
    result = analyze_logs("tests/time_window.log")
    alerts = result["alerts"]

    assert len(alerts) == 0

def test_detection_engine_brute_force():
    engine = DetectionEngine()

    timestamps = [
        datetime(2026, 9, 15, 10, 21, 1),
        datetime(2026, 9, 15, 10, 21, 5),
        datetime(2026, 9, 15, 10, 21, 9)
    ]

    alert = engine.detect_brute_force(
        username="admin",
        ip_address="192.168.1.50",
        timestamps=timestamps,
        threshold=3,
        window_minutes=5,
        successful_login=True
    )

    assert alert is not None
    assert alert["type"] == "SSH Brute Force"
    assert alert["risk"] == "CRITICAL"
    assert alert["failed_attempts"] == 3

def test_password_spraying_detection():
    engine = DetectionEngine()

    username_attempts = {
        "admin",
        "root",
        "testuser"
    }

    alert = engine.detect_password_spraying(
        ip_address="10.10.10.50",
        username_attempts=username_attempts,
        threshold=3,
        timestamp=datetime(2026, 9, 15, 13, 0, 4)
    )

    assert alert is not None
    assert alert["type"] == "SSH Password Spraying"
    assert alert["ip"] == "10.10.10.50"
    assert alert["targeted_user_count"] == 3
    assert alert["risk"] == "HIGH"

def test_incident_generation():
    result = analyze_logs()

    incidents = result["incidents"]

    assert len(incidents) == 2

    assert incidents[0]["type"] == "Potential Account Compromise"
    assert incidents[0]["source_ip"] == "192.168.1.50"
    assert incidents[0]["risk"] == "CRITICAL"
    assert incidents[0]["status"] == "OPEN"

    assert incidents[1]["type"] == "SSH Brute Force Incident"
    assert incidents[1]["source_ip"] == "10.10.10.25"
    assert incidents[1]["risk"] == "MEDIUM"
    assert incidents[1]["status"] == "OPEN"