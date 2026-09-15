import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.detection_engine import SecurityAlert
from analyzer.mitre_mapper import MitreMapper


def test_brute_force_mitre_mapping():

    mapper = MitreMapper()

    alert = SecurityAlert(
        type="SSH Brute Force",
        timestamp=None,
        username="admin",
        ip="192.168.1.50",
        failed_attempts=3,
        successful_login=True,
        risk="CRITICAL"
    )

    result = mapper.map_alert(alert)

    assert result["mitre"]["technique_id"] == "T1110"
    assert result["mitre"]["technique"] == "Brute Force"
    assert result["mitre"]["tactic"] == "Credential Access"


def test_password_spraying_mitre_mapping():

    mapper = MitreMapper()

    alert = SecurityAlert(
        type="SSH Password Spraying",
        timestamp=None,
        username="admin, root, testuser",
        ip="10.10.10.50",
        failed_attempts=3,
        successful_login=False,
        risk="HIGH",
        targeted_users=["admin", "root", "testuser"]
    )

    result = mapper.map_alert(alert)

    assert result["mitre"]["technique_id"] == "T1110.003"
    assert result["mitre"]["technique"] == "Password Spraying"
    assert result["mitre"]["tactic"] == "Credential Access"


def test_unknown_alert_mitre_mapping():

    mapper = MitreMapper()

    alert = SecurityAlert(
        type="Unknown Detection",
        timestamp=None,
        username="test",
        ip="10.0.0.1",
        failed_attempts=1,
        successful_login=False,
        risk="LOW"
    )

    result = mapper.map_alert(alert)

    assert result["mitre"]["technique_id"] == "UNKNOWN"
    assert result["mitre"]["technique"] == "Unknown"
    assert result["mitre"]["tactic"] == "Unknown"