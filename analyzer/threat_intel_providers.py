from abc import ABC, abstractmethod

from analyzer.threat_intel_models import ThreatIntelResult


class ThreatIntelProvider(ABC):
    name = "Unknown"

    @abstractmethod
    def supports(self, ioc_type: str) -> bool:
        pass

    @abstractmethod
    def lookup(self, value: str, ioc_type: str) -> ThreatIntelResult | None:
        pass


class ThreatIntelProviderManager:
    def __init__(self, providers=None):
        self.providers = providers or []

    def add_provider(self, provider: ThreatIntelProvider):
        self.providers.append(provider)

    def get_providers(self, ioc_type: str):
        return [
            provider
            for provider in self.providers
            if provider.supports(ioc_type)
        ]

    def lookup(self, value: str, ioc_type: str):
        results = []

        for provider in self.get_providers(ioc_type):
            result = provider.lookup(value, ioc_type)

            if result is not None:
                results.append(result)

        return results