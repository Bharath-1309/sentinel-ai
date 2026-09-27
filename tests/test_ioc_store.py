from datetime import datetime

from analyzer.ioc_store import IOCStore
from analyzer.threat_intel_models import IOC, ThreatIntelResult


def test_add_and_get_ioc():
    store = IOCStore()

    ioc = IOC(
        value="8.8.8.8",
        ioc_type="ip",
    )

    store.add_ioc(ioc)

    result = store.get_ioc("8.8.8.8")

    assert result is not None
    assert result.value == "8.8.8.8"
    assert result.ioc_type == "ip"


def test_list_iocs():
    store = IOCStore()

    store.add_ioc(IOC("8.8.8.8", "ip"))
    store.add_ioc(IOC("example.com", "domain"))

    results = store.list_iocs()

    assert len(results) == 2


def test_remove_ioc():
    store = IOCStore()

    store.add_ioc(IOC("8.8.8.8", "ip"))

    assert store.remove_ioc("8.8.8.8") is True
    assert store.get_ioc("8.8.8.8") is None


def test_remove_missing_ioc():
    store = IOCStore()

    assert store.remove_ioc("8.8.8.8") is False


def test_save_and_get_threat_intel_result():
    store = IOCStore()

    result = ThreatIntelResult(
        value="8.8.8.8",
        ioc_type="ip",
        malicious=True,
        confidence=90,
        threat="Reported Malicious IP",
        source="AbuseIPDB",
    )

    store.save_result(result)

    stored = store.get_result("8.8.8.8")

    assert stored is not None
    assert stored.malicious is True
    assert stored.confidence == 90


def test_list_results():
    store = IOCStore()

    store.save_result(
        ThreatIntelResult(
            value="8.8.8.8",
            ioc_type="ip",
            malicious=True,
            confidence=90,
            threat="Malicious IP",
            source="AbuseIPDB",
        )
    )

    store.save_result(
        ThreatIntelResult(
            value="example.com",
            ioc_type="domain",
            malicious=False,
            confidence=0,
            threat=None,
            source="Test",
        )
    )

    assert len(store.list_results()) == 2


def test_update_result_timestamps():
    store = IOCStore()

    result = ThreatIntelResult(
        value="8.8.8.8",
        ioc_type="ip",
        malicious=True,
        confidence=90,
        threat="Malicious IP",
        source="AbuseIPDB",
    )

    store.save_result(result)

    first_seen = datetime(2026, 9, 1, 10, 0, 0)
    last_seen = datetime(2026, 9, 20, 18, 0, 0)

    updated = store.update_result_timestamps(
        "8.8.8.8",
        first_seen=first_seen,
        last_seen=last_seen,
    )

    assert updated is not None
    assert updated.first_seen == first_seen
    assert updated.last_seen == last_seen


def test_update_missing_result():
    store = IOCStore()

    result = store.update_result_timestamps(
        "8.8.8.8",
        first_seen=datetime(2026, 9, 1),
    )

    assert result is None


def test_remove_ioc_also_removes_result():
    store = IOCStore()

    store.add_ioc(IOC("8.8.8.8", "ip"))
    store.save_result(
        ThreatIntelResult(
            value="8.8.8.8",
            ioc_type="ip",
            malicious=True,
            confidence=90,
            threat="Malicious IP",
            source="AbuseIPDB",
        )
    )

    store.remove_ioc("8.8.8.8")

    assert store.get_ioc("8.8.8.8") is None
    assert store.get_result("8.8.8.8") is None