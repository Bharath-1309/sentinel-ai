import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.threat_intel import ThreatIntelligence


def test_abuseipdb_malicious_ip_response(monkeypatch):

    threat_intel = ThreatIntelligence()

    threat_intel.api_key = "test-api-key"

    class MockResponse:

        status_code = 200

        def json(self):
            return {
                "data": {
                    "abuseConfidenceScore": 85
                }
            }

    def mock_get(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr(
        "analyzer.threat_intel.requests.get",
        mock_get
    )

    result = threat_intel.lookup_ip("8.8.8.8")

    assert result["ip"] == "8.8.8.8"
    assert result["malicious"] is True
    assert result["confidence"] == 85
    assert result["threat"] == "Reported Malicious IP"
    assert result["source"] == "AbuseIPDB"


def test_abuseipdb_failure_returns_safe_result(monkeypatch):

    threat_intel = ThreatIntelligence()

    threat_intel.api_key = "test-api-key"

    def mock_get(*args, **kwargs):
        raise Exception("API unavailable")

    monkeypatch.setattr(
        "analyzer.threat_intel.requests.get",
        mock_get
    )

    result = threat_intel.lookup_ip("8.8.8.8")

    assert result["ip"] == "8.8.8.8"
    assert result["malicious"] is False
    assert result["confidence"] == 0
    assert result["source"] == "AbuseIPDB (unavailable)"