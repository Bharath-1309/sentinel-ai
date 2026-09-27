from analyzer.ioc_store import IOCStore
from analyzer.ioc_validator import classify_ioc, normalize_ioc
from analyzer.threat_intel import ThreatIntelligence
from analyzer.threat_intel_models import IOC


class IOCEnrichmentEngine:
    def __init__(self, threat_intelligence=None, store=None):
        self.threat_intelligence = (
            threat_intelligence or ThreatIntelligence()
        )
        self.store = store or IOCStore()

    def create_ioc(self, value: str) -> IOC | None:
        normalized = normalize_ioc(value)
        ioc_type = classify_ioc(normalized)

        if ioc_type is None:
            return None

        return IOC(
            value=normalized,
            ioc_type=ioc_type,
        )

    def enrich(self, value: str) -> dict:
        ioc = self.create_ioc(value)

        if ioc is None:
            return {
                "value": value,
                "ioc_type": None,
                "valid": False,
                "enriched": False,
                "result": None,
            }

        self.store.add_ioc(ioc)

        if ioc.ioc_type != "ip":
            return {
                "value": ioc.value,
                "ioc_type": ioc.ioc_type,
                "valid": True,
                "enriched": False,
                "result": None,
            }

        result = self.threat_intelligence.lookup_aggregated(
            ioc.value,
            ioc.ioc_type,
        )

        if result is None:
            return {
                "value": ioc.value,
                "ioc_type": ioc.ioc_type,
                "valid": True,
                "enriched": False,
                "result": None,
            }

        self.store.save_result(result)

        return {
            "value": ioc.value,
            "ioc_type": ioc.ioc_type,
            "valid": True,
            "enriched": True,
            "result": {
                "value": result.value,
                "ioc_type": result.ioc_type,
                "malicious": result.malicious,
                "confidence": result.confidence,
                "threat": result.threat,
                "source": result.source,
                "first_seen": result.first_seen,
                "last_seen": result.last_seen,
                "tags": result.tags,
                "provider_results": result.provider_results,
            },
        }

    def get_ioc(self, value: str):
        return self.store.get_ioc(
            normalize_ioc(value)
        )

    def get_result(self, value: str):
        return self.store.get_result(
            normalize_ioc(value)
        )

    def list_iocs(self):
        return self.store.list_iocs()

    def list_results(self):
        return self.store.list_results()

    def remove_ioc(self, value: str) -> bool:
        return self.store.remove_ioc(
            normalize_ioc(value)
        )