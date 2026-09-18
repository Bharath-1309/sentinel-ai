from analyzer.log_analyzer import analyze_logs


def test_windows_password_spraying_integration():
    result = analyze_logs(
        "tests/windows_password_spray.log"
    )

    assert len(result["alerts"]) == 1

    alert = result["alerts"][0]

    assert alert["type"] == "Windows Password Spraying"
    assert alert["ip"] == "192.168.1.60"
    assert alert["failed_attempts"] == 4
    assert alert["risk"] == "HIGH"

    assert alert["mitre"]["technique_id"] == "T1110.003"
    assert alert["mitre"]["technique"] == "Password Spraying"
    assert alert["mitre"]["tactic"] == "Credential Access"