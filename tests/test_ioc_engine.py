from analyzer.ioc_engine import IOCEnrichmentEngine


class FakeThreatIntelligence:
    def lookup_aggregated(self, value, ioc_type):
        from analyzer.threat_intel_models import ThreatIntelResult

        return ThreatIntelResult(
            value=value,
            ioc_type=ioc_type,
            malicious=True,
            confidence=90,
            threat="Reported Malicious IP",
            source="FakeTI",
            tags=["malicious-ip"],
            provider_results=[
                {
                    "source": "FakeTI",
                    "malicious": True,
                    "confidence": 90,
                    "threat": "Reported Malicious IP",
                    "tags": ["malicious-ip"],
                }
            ],
        )


def test_create_valid_ip_ioc():
    engine = IOCEnrichmentEngine(FakeThreatIntelligence())

    ioc = engine.create_ioc(" 8.8.8.8 ")

    assert ioc is not None
    assert ioc.value == "8.8.8.8"
    assert ioc.ioc_type == "ip"


def test_create_valid_domain_ioc():
    engine = IOCEnrichmentEngine(FakeThreatIntelligence())

    ioc = engine.create_ioc("example.com")

    assert ioc is not None
    assert ioc.value == "example.com"
    assert ioc.ioc_type == "domain"


def test_create_invalid_ioc():
    engine = IOCEnrichmentEngine(FakeThreatIntelligence())

    ioc = engine.create_ioc("not-an-ioc")

    assert ioc is None


def test_enrich_ip():
    engine = IOCEnrichmentEngine(FakeThreatIntelligence())

    result = engine.enrich("8.8.8.8")

    assert result["valid"] is True
    assert result["enriched"] is True
    assert result["ioc_type"] == "ip"
    assert result["result"]["malicious"] is True
    assert result["result"]["confidence"] == 90


def test_enrich_ip_is_stored():
    engine = IOCEnrichmentEngine(FakeThreatIntelligence())

    engine.enrich("8.8.8.8")

    ioc = engine.get_ioc("8.8.8.8")
    stored_result = engine.get_result("8.8.8.8")

    assert ioc is not None
    assert ioc.ioc_type == "ip"

    assert stored_result is not None
    assert stored_result.malicious is True
    assert stored_result.confidence == 90


def test_provider_evidence_is_returned():
    engine = IOCEnrichmentEngine(FakeThreatIntelligence())

    result = engine.enrich("8.8.8.8")

    assert len(result["result"]["provider_results"]) == 1
    assert (
        result["result"]["provider_results"][0]["source"]
        == "FakeTI"
    )
    assert (
        result["result"]["provider_results"][0]["confidence"]
        == 90
    )


def test_provider_evidence_is_stored():
    engine = IOCEnrichmentEngine(FakeThreatIntelligence())

    engine.enrich("8.8.8.8")

    stored_result = engine.get_result("8.8.8.8")

    assert stored_result is not None
    assert len(stored_result.provider_results) == 1
    assert stored_result.provider_results[0]["source"] == "FakeTI"


def test_non_ip_ioc_is_stored():
    engine = IOCEnrichmentEngine(FakeThreatIntelligence())

    result = engine.enrich("example.com")

    assert result["valid"] is True
    assert result["enriched"] is False
    assert result["ioc_type"] == "domain"

    ioc = engine.get_ioc("example.com")

    assert ioc is not None
    assert ioc.ioc_type == "domain"


def test_invalid_ioc_enrichment():
    engine = IOCEnrichmentEngine(FakeThreatIntelligence())

    result = engine.enrich("definitely-invalid")

    assert result["valid"] is False
    assert result["enriched"] is False
    assert result["ioc_type"] is None
    assert result["result"] is None

    assert engine.get_ioc("definitely-invalid") is None


def test_list_iocs():
    engine = IOCEnrichmentEngine(FakeThreatIntelligence())

    engine.enrich("8.8.8.8")
    engine.enrich("example.com")

    iocs = engine.list_iocs()

    assert len(iocs) == 2


def test_list_results():
    engine = IOCEnrichmentEngine(FakeThreatIntelligence())

    engine.enrich("8.8.8.8")

    results = engine.list_results()

    assert len(results) == 1
    assert results[0].confidence == 90


def test_remove_ioc():
    engine = IOCEnrichmentEngine(FakeThreatIntelligence())

    engine.enrich("8.8.8.8")

    assert engine.remove_ioc("8.8.8.8") is True
    assert engine.get_ioc("8.8.8.8") is None
    assert engine.get_result("8.8.8.8") is None