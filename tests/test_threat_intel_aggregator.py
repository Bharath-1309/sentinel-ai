from analyzer.threat_intel_aggregator import ThreatIntelAggregator
from analyzer.threat_intel_models import ThreatIntelResult


def make_result(
    source,
    malicious,
    confidence,
    threat=None,
    tags=None,
):
    return ThreatIntelResult(
        value="8.8.8.8",
        ioc_type="ip",
        malicious=malicious,
        confidence=confidence,
        threat=threat,
        source=source,
        tags=tags or [],
    )


def test_empty_results():
    aggregator = ThreatIntelAggregator()

    assert aggregator.aggregate([]) is None


def test_single_result():
    aggregator = ThreatIntelAggregator()

    result = aggregator.aggregate([
        make_result(
            "ProviderA",
            True,
            85,
            "Malicious IP",
        )
    ])

    assert result is not None
    assert result.malicious is True
    assert result.confidence == 85
    assert result.source == "ProviderA"


def test_multiple_results():
    aggregator = ThreatIntelAggregator()

    result = aggregator.aggregate([
        make_result(
            "ProviderA",
            True,
            70,
            "Known malicious",
        ),
        make_result(
            "ProviderB",
            True,
            90,
            "Abuse activity",
        ),
    ])

    assert result is not None
    assert result.malicious is True
    assert result.confidence == 90
    assert "ProviderA" in result.source
    assert "ProviderB" in result.source


def test_any_malicious_result_marks_aggregated_result_malicious():
    aggregator = ThreatIntelAggregator()

    result = aggregator.aggregate([
        make_result(
            "ProviderA",
            False,
            10,
        ),
        make_result(
            "ProviderB",
            True,
            60,
            "Malicious",
        ),
    ])

    assert result.malicious is True
    assert result.confidence == 60


def test_no_threats():
    aggregator = ThreatIntelAggregator()

    result = aggregator.aggregate([
        make_result(
            "ProviderA",
            False,
            0,
        ),
        make_result(
            "ProviderB",
            False,
            5,
        ),
    ])

    assert result.malicious is False
    assert result.confidence == 5
    assert result.threat is None


def test_provider_evidence_is_preserved():
    aggregator = ThreatIntelAggregator()

    result = aggregator.aggregate([
        make_result(
            "ProviderA",
            True,
            80,
            "Malicious IP",
            ["botnet"],
        ),
        make_result(
            "ProviderB",
            False,
            20,
            tags=["scanner"],
        ),
    ])

    assert result.provider_results is not None
    assert len(result.provider_results) == 2

    assert result.provider_results[0]["source"] == "ProviderA"
    assert result.provider_results[0]["malicious"] is True
    assert result.provider_results[0]["confidence"] == 80

    assert result.provider_results[1]["source"] == "ProviderB"
    assert result.provider_results[1]["malicious"] is False


def test_tags_are_merged_without_duplicates():
    aggregator = ThreatIntelAggregator()

    result = aggregator.aggregate([
        make_result(
            "ProviderA",
            True,
            80,
            tags=["botnet", "scanner"],
        ),
        make_result(
            "ProviderB",
            True,
            70,
            tags=["scanner", "malware"],
        ),
    ])

    assert result.tags == [
        "botnet",
        "scanner",
        "malware",
    ]