from analyzer.log_analyzer import analyze_logs


def test_network_scan_integration():
    result = analyze_logs(
        "tests/network_scan.log"
    )

    assert len(result["alerts"]) == 1

    alert = result["alerts"][0]

    assert alert["type"] == "Network Service Scanning"
    assert alert["ip"] == "192.168.1.70"
    assert alert["failed_attempts"] == 5
    assert alert["risk"] == "HIGH"

    assert alert["mitre"]["technique_id"] == "T1046"
    assert alert["mitre"]["technique"] == "Network Service Scanning"
    assert alert["mitre"]["tactic"] == "Discovery"