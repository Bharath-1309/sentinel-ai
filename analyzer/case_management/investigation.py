from analyzer.ai_agent import AISOCAgent


class CaseInvestigationService:
    def __init__(self, ai_agent=None):
        self.ai_agent = ai_agent or AISOCAgent()

    @staticmethod
    def _extract_source_ip(case):
        # Incident -> Case currently stores the source IP
        # as SOURCE_IP evidence.
        for item in case.evidence:
            if item.evidence_type.upper() == "SOURCE_IP":
                return item.value

        # Backward-compatible fallback for cases that store
        # the source IP inside the IOC list.
        if case.iocs:
            return case.iocs[0]

        return "UNKNOWN"

    @staticmethod
    def _build_incident_context(case):
        evidence = []

        for item in case.evidence:
            evidence.append(
                {
                    "evidence_type": item.evidence_type,
                    "value": item.value,
                    "source": item.source,
                    "created_at": item.created_at.isoformat(),
                }
            )

        return {
            "incident_id": case.incident_id,
            "case_id": case.case_id,
            "type": case.title,
            "risk": case.severity,
            "source_ip": CaseInvestigationService._extract_source_ip(case),
            "description": case.description,
            "evidence": evidence,
            "mitre_techniques": case.mitre_techniques,
        }

    def investigate(self, case):
        if case is None:
            raise ValueError("Case is required")

        incident = self._build_incident_context(case)

        return self.ai_agent.investigate(incident)