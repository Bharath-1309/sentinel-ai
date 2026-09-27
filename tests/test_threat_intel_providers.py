from analyzer.threat_intel_models import ThreatIntelResult
from analyzer.threat_intel_providers import (
    ThreatIntelProvider,
    ThreatIntelProviderManager,
)


class FakeProvider(ThreatIntelProvider):
    name = "FakeProvider"

    def __init__(self, supported_type="ip"):
        self.supported_type = supported_type

    def supports(self, ioc_type: str) -> bool:
        return ioc_type == self.supported_type

    def lookup(self, value: str, ioc_type: str):
        return ThreatIntelResult(
            value=value,
            ioc_type=ioc_type,
            malicious=True,
            confidence=85,
            threat="Test Threat",
            source=self.name,
        )


def test_provider_supports_ioc_type():
    provider = FakeProvider("ip")

    assert provider.supports("ip") is True
    assert provider.supports("domain") is False


def test_manager_add_provider():
    manager = ThreatIntelProviderManager()

    provider = FakeProvider()

    manager.add_provider(provider)

    assert len(manager.providers) == 1


def test_manager_get_providers():
    manager = ThreatIntelProviderManager()

    manager.add_provider(FakeProvider("ip"))
    manager.add_provider(FakeProvider("domain"))

    ip_providers = manager.get_providers("ip")
    domain_providers = manager.get_providers("domain")

    assert len(ip_providers) == 1
    assert len(domain_providers) == 1


def test_manager_lookup():
    manager = ThreatIntelProviderManager()

    manager.add_provider(FakeProvider("ip"))

    results = manager.lookup("8.8.8.8", "ip")

    assert len(results) == 1
    assert results[0].value == "8.8.8.8"
    assert results[0].malicious is True
    assert results[0].confidence == 85


def test_manager_lookup_unsupported_type():
    manager = ThreatIntelProviderManager()

    manager.add_provider(FakeProvider("ip"))

    results = manager.lookup("example.com", "domain")

    assert results == []