from analyzer.log_analyzer import analyze_logs


def test_windows_authentication_integration():
    result = analyze_logs("tests/windows_auth.log")

    assert len(result["alerts"]) == 1

    alert = result["alerts"][0]

    assert alert["type"] == "Windows Authentication Brute Force"
    assert alert["username"] == "administrator"
    assert alert["ip"] == "192.168.1.50"
    assert alert["failed_attempts"] == 5
    assert alert["risk"] == "HIGH"

    assert alert["mitre"]["technique_id"] == "T1110"
    assert alert["mitre"]["technique"] == "Brute Force"
    assert alert["mitre"]["tactic"] == "Credential Access"