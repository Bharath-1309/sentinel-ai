import os
import requests

from analyzer.threat_intel_models import ThreatIntelResult
from analyzer.threat_intel_providers import ThreatIntelProvider
from analyzer.threat_intel_aggregator import ThreatIntelAggregator


class AbuseIPDBProvider(ThreatIntelProvider):
    name = "AbuseIPDB"

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")

    def supports(self, ioc_type: str) -> bool:
        return ioc_type == "ip"

    def lookup(
        self,
        value: str,
        ioc_type: str,
    ) -> ThreatIntelResult | None:

        if not self.api_key:
            return ThreatIntelResult(
                value=value,
                ioc_type=ioc_type,
                malicious=False,
                confidence=0,
                threat=None,
                source=self.name,
            )

        headers = {
            "Accept": "application/json",
            "Key": self.api_key,
        }

        params = {
            "ipAddress": value,
            "maxAgeInDays": 90,
        }

        try:
            response = requests.get(
                self.API_URL,
                headers=headers,
                params=params,
                timeout=5,
            )

            if response.status_code != 200:
                return None

            data = response.json()["data"]

            confidence = data.get(
                "abuseConfidenceScore",
                0,
            )

            malicious = confidence > 0

            return ThreatIntelResult(
                value=value,
                ioc_type=ioc_type,
                malicious=malicious,
                confidence=confidence,
                threat=(
                    "Reported Malicious IP"
                    if malicious
                    else None
                ),
                source=self.name,
            )

        except Exception:
            return ThreatIntelResult(
                value=value,
                ioc_type=ioc_type,
                malicious=False,
                confidence=0,
                threat=None,
                source=f"{self.name} (unavailable)",
            )


class ThreatIntelligence:
    def __init__(self, providers=None, aggregator=None):
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")

        if providers is not None:
            self.providers = providers
        else:
            self.providers = [
                AbuseIPDBProvider(
                    api_key=self.api_key
                )
            ]

        self.aggregator = (
            aggregator
            if aggregator is not None
            else ThreatIntelAggregator()
        )

    def _sync_provider_credentials(self):
        for provider in self.providers:
            if isinstance(provider, AbuseIPDBProvider):
                provider.api_key = self.api_key

    def lookup(self, value: str, ioc_type: str):
        self._sync_provider_credentials()

        results = []

        for provider in self.providers:
            if not provider.supports(ioc_type):
                continue

            result = provider.lookup(
                value,
                ioc_type,
            )

            if result is not None:
                results.append(result)

        return results

    def lookup_aggregated(
        self,
        value: str,
        ioc_type: str,
    ):
        results = self.lookup(
            value,
            ioc_type,
        )

        return self.aggregator.aggregate(results)

    def lookup_ip(self, ip_address):
        result = self.lookup_aggregated(
            ip_address,
            "ip",
        )

        if result is None:
            return None

        return {
            "ip": result.value,
            "malicious": result.malicious,
            "threat": result.threat,
            "confidence": result.confidence,
            "source": result.source,
        }