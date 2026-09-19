import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.risk_engine import RiskEngine


def test_critical_risk_for_successful_brute_force():

    engine = RiskEngine()

    alerts = [
        {
            "type": "SSH Brute Force",
            "failed_attempts": 5,
            "successful_login": True,
            "risk": "CRITICAL"
        }
    ]

    result = engine.calculate_score(alerts)

    assert result["score"] == 100
    assert result["risk"] == "CRITICAL"


def test_high_risk_for_password_spraying():

    engine = RiskEngine()

    alerts = [
        {
            "type": "SSH Password Spraying",
            "failed_attempts": 3,
            "successful_login": False,
            "risk": "HIGH"
        }
    ]

    result = engine.calculate_score(alerts)

    assert result["score"] == 50
    assert result["risk"] == "MEDIUM"


def test_low_risk_for_no_alerts():

    engine = RiskEngine()

    result = engine.calculate_score([])

    assert result["score"] == 0
    assert result["risk"] == "LOW"

def test_malicious_ip_increases_risk():

    engine = RiskEngine()

    alerts = [
        {
            "type": "SSH Brute Force",
            "failed_attempts": 4,
            "successful_login": False,
            "risk": "MEDIUM",
            "threat_intelligence": {
                "malicious": True,
                "confidence": 85
            }
        }
    ]

    result = engine.calculate_score(alerts)

    assert result["score"] == 50
    assert result["risk"] == "MEDIUM"

def test_network_scan_risk_score():
    engine = RiskEngine()

    alert = {
        "type": "Network Service Scanning",
        "failed_attempts": 5,
        "successful_login": False,
        "risk": "HIGH",
    }

    result = engine.calculate_score([alert])

    assert result["score"] == 35
    assert result["risk"] == "MEDIUM"


def test_credential_dumping_risk_score():
    engine = RiskEngine()

    alert = {
        "type": "Credential Dumping",
        "failed_attempts": 2,
        "successful_login": False,
        "risk": "CRITICAL",
    }

    result = engine.calculate_score([alert])

    assert result["score"] == 80
    assert result["risk"] == "CRITICAL"


def test_windows_brute_force_risk_score():
    engine = RiskEngine()

    alert = {
        "type": "Windows Authentication Brute Force",
        "failed_attempts": 10,
        "successful_login": False,
        "risk": "CRITICAL",
    }

    result = engine.calculate_score([alert])

    assert result["score"] == 60
    assert result["risk"] == "HIGH"


def test_windows_password_spraying_risk_score():
    engine = RiskEngine()

    alert = {
        "type": "Windows Password Spraying",
        "failed_attempts": 5,
        "successful_login": False,
        "risk": "HIGH",
    }

    result = engine.calculate_score([alert])

    assert result["score"] == 60
    assert result["risk"] == "HIGH"


def test_powershell_risk_score():
    engine = RiskEngine()

    alert = {
        "type": "Suspicious PowerShell",
        "failed_attempts": 0,
        "successful_login": False,
        "risk": "HIGH",
    }

    result = engine.calculate_score([alert])

    assert result["score"] == 40
    assert result["risk"] == "MEDIUM"        