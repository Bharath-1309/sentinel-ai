from analyzer.threat_intel_models import (
    IOC,
    ThreatIntelResult,
)


def test_ioc_creation():

    ioc = IOC(
        value="8.8.8.8",
        ioc_type="ip",
    )

    assert ioc.value == "8.8.8.8"
    assert ioc.ioc_type == "ip"


def test_threat_intel_result_creation():

    result = ThreatIntelResult(
        value="8.8.8.8",
        ioc_type="ip",
        malicious=True,
        confidence=85,
        threat="Reported Malicious IP",
        source="AbuseIPDB",
        tags=["malicious", "network"],
    )

    assert result.value == "8.8.8.8"
    assert result.ioc_type == "ip"
    assert result.malicious is True
    assert result.confidence == 85
    assert result.threat == "Reported Malicious IP"
    assert result.source == "AbuseIPDB"
    assert result.tags == [
        "malicious",
        "network",
    ]


def test_threat_intel_result_defaults():

    result = ThreatIntelResult(
        value="example.com",
        ioc_type="domain",
        malicious=False,
        confidence=0,
        threat=None,
        source="internal",
    )

    assert result.first_seen is None
    assert result.last_seen is None
    assert result.tags == []