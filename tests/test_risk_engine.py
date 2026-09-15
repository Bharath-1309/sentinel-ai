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