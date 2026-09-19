import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from datetime import datetime

from analyzer.correlation_engine import CorrelationEngine
from analyzer.correlation_engine import CorrelationEngine
from analyzer.detection_engine import SecurityAlert

def test_successful_brute_force_creates_account_compromise():

    engine = CorrelationEngine()

    alerts = [
        {
            "type": "SSH Brute Force",
            "timestamp": datetime(2026, 9, 15, 10, 21, 9),
            "username": "admin",
            "ip": "192.168.1.50",
            "failed_attempts": 3,
            "successful_login": True,
            "risk": "CRITICAL"
        }
    ]

    incidents = engine.correlate(alerts)

    assert len(incidents) == 1
    assert incidents[0]["type"] == "Potential Account Compromise"
    assert incidents[0]["source_ip"] == "192.168.1.50"
    assert incidents[0]["risk"] == "CRITICAL"


def test_brute_force_and_password_spraying_create_coordinated_attack():

    engine = CorrelationEngine()

    alerts = [
        {
            "type": "SSH Brute Force",
            "timestamp": datetime(2026, 9, 15, 10, 21, 9),
            "username": "admin",
            "ip": "10.10.10.50",
            "failed_attempts": 3,
            "successful_login": False,
            "risk": "MEDIUM"
        },
        {
            "type": "SSH Password Spraying",
            "timestamp": datetime(2026, 9, 15, 10, 21, 9),
            "username": "admin, root, testuser",
            "ip": "10.10.10.50",
            "failed_attempts": 3,
            "successful_login": False,
            "risk": "HIGH"
        }
    ]

    incidents = engine.correlate(alerts)

    assert len(incidents) == 1
    assert incidents[0]["type"] == "Coordinated SSH Attack"
    assert incidents[0]["source_ip"] == "10.10.10.50"
    assert incidents[0]["risk"] == "CRITICAL"



def test_credential_dumping_creates_incident():
    engine = CorrelationEngine()

    alert = SecurityAlert(
        type="Credential Dumping",
        timestamp=None,
        username="administrator",
        ip="192.168.1.80",
        failed_attempts=2,
        successful_login=False,
        risk="CRITICAL"
    )

    incidents = engine.correlate([alert])

    assert len(incidents) == 1
    assert incidents[0]["type"] == "Credential Theft Activity"
    assert incidents[0]["source_ip"] == "192.168.1.80"
    assert incidents[0]["risk"] == "CRITICAL"


def test_network_scan_creates_incident():
    engine = CorrelationEngine()

    alert = SecurityAlert(
        type="Network Service Scanning",
        timestamp=None,
        username=None,
        ip="192.168.1.70",
        failed_attempts=5,
        successful_login=False,
        risk="HIGH"
    )

    incidents = engine.correlate([alert])

    assert len(incidents) == 1
    assert incidents[0]["type"] == "Network Reconnaissance"
    assert incidents[0]["source_ip"] == "192.168.1.70"
    assert incidents[0]["risk"] == "HIGH"

def test_network_scan_and_credential_dumping_create_host_compromise():

    engine = CorrelationEngine()

    scan_alert = SecurityAlert(
        type="Network Service Scanning",
        timestamp=None,
        username=None,
        ip="192.168.1.80",
        failed_attempts=5,
        successful_login=False,
        risk="HIGH"
    )

    dumping_alert = SecurityAlert(
        type="Credential Dumping",
        timestamp=None,
        username="administrator",
        ip="192.168.1.80",
        failed_attempts=2,
        successful_login=False,
        risk="CRITICAL"
    )

    incidents = engine.correlate([
        scan_alert,
        dumping_alert
    ])

    assert len(incidents) == 1
    assert incidents[0]["type"] == "Potential Host Compromise"
    assert incidents[0]["source_ip"] == "192.168.1.80"
    assert incidents[0]["risk"] == "CRITICAL"
    assert incidents[0]["alert_count"] == 2    