from datetime import datetime

from analyzer.threat_intel_models import IOC, ThreatIntelResult


class IOCStore:
    def __init__(self):
        self._iocs: dict[str, IOC] = {}
        self._results: dict[str, ThreatIntelResult] = {}

    def add_ioc(self, ioc: IOC) -> IOC:
        self._iocs[ioc.value] = ioc
        return ioc

    def get_ioc(self, value: str) -> IOC | None:
        return self._iocs.get(value)

    def list_iocs(self) -> list[IOC]:
        return list(self._iocs.values())

    def remove_ioc(self, value: str) -> bool:
        if value not in self._iocs:
            return False

        del self._iocs[value]
        self._results.pop(value, None)
        return True

    def save_result(self, result: ThreatIntelResult) -> ThreatIntelResult:
        self._results[result.value] = result
        return result

    def get_result(self, value: str) -> ThreatIntelResult | None:
        return self._results.get(value)

    def list_results(self) -> list[ThreatIntelResult]:
        return list(self._results.values())

    def update_result_timestamps(
        self,
        value: str,
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
    ) -> ThreatIntelResult | None:
        result = self._results.get(value)

        if result is None:
            return None

        if first_seen is not None:
            result.first_seen = first_seen

        if last_seen is not None:
            result.last_seen = last_seen

        return result