from analyzer.log_analyzer import analyze_logs


def test_credential_dumping_integration():
    result = analyze_logs(
        "tests/credential_dumping.log"
    )

    assert len(result["alerts"]) == 1

    alert = result["alerts"][0]

    assert alert["type"] == "Credential Dumping"
    assert alert["ip"] == "192.168.1.80"
    assert alert["risk"] == "CRITICAL"
    assert alert["failed_attempts"] == 2
    assert alert["mitre"]["technique_id"] == "T1003"
    assert alert["mitre"]["technique"] == "OS Credential Dumping"
    assert alert["mitre"]["tactic"] == "Credential Access"