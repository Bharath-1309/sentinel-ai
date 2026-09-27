from analyzer.threat_intel_models import ThreatIntelResult


class ThreatIntelAggregator:
    def aggregate(
        self,
        results: list[ThreatIntelResult],
    ) -> ThreatIntelResult | None:

        if not results:
            return None

        malicious = any(
            result.malicious
            for result in results
        )

        confidence = max(
            result.confidence
            for result in results
        )

        threats = [
            result.threat
            for result in results
            if result.threat
        ]

        sources = [
            result.source
            for result in results
        ]

        primary = max(
            results,
            key=lambda result: result.confidence,
        )

        provider_results = [
            {
                "source": result.source,
                "malicious": result.malicious,
                "confidence": result.confidence,
                "threat": result.threat,
                "tags": result.tags,
            }
            for result in results
        ]

        return ThreatIntelResult(
            value=primary.value,
            ioc_type=primary.ioc_type,
            malicious=malicious,
            confidence=confidence,
            threat=(
                "; ".join(threats)
                if threats
                else None
            ),
            source=", ".join(sources),
            first_seen=primary.first_seen,
            last_seen=primary.last_seen,
            tags=list(
                dict.fromkeys(
                    tag
                    for result in results
                    for tag in result.tags
                )
            ),
            provider_results=provider_results,
        )