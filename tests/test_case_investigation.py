from datetime import datetime

from analyzer.case_management.investigation import CaseInvestigationService
from analyzer.case_management.models import Case, CaseEvidence


class MockAIAgent:
    def __init__(self):
        self.received_incident = None

    def investigate(self, incident):
        self.received_incident = incident

        return {
            "incident_id": incident["incident_id"],
            "type": incident["type"],
            "risk": incident["risk"],
            "source_ip": incident["source_ip"],
            "investigation_status": "COMPLETED",
            "analysis": "Mock investigation completed.",
            "recommendations": [
                "Investigate the source IP",
                "Review authentication logs",
                "Contain the affected account",
            ],
        }


def build_case(source_ip_in_ioc=False):
    iocs = ["192.168.1.50"] if source_ip_in_ioc else []

    evidence = [
        CaseEvidence(
            evidence_id=1,
            evidence_type="SOURCE_IP",
            value="192.168.1.80",
            source="INCIDENT",
            created_at=datetime.now(),
        ),
        CaseEvidence(
            evidence_id=2,
            evidence_type="MITRE_TECHNIQUE",
            value="T1110",
            source="INCIDENT",
            created_at=datetime.now(),
        ),
    ]

    return Case(
        case_id="CASE-12345678",
        incident_id="INC-20260917140003",
        title="Credential Theft Activity",
        description="Credential attack investigation",
        severity="CRITICAL",
        status="OPEN",
        assigned_to=None,
        created_at=datetime.now(),
        updated_at=datetime.now(),
        notes=[],
        evidence=evidence,
        iocs=iocs,
        mitre_techniques=[
            {
                "technique_id": "T1110",
                "technique": "Brute Force",
                "tactic": "Credential Access",
            }
        ],
        ai_investigation=None,
    )


def test_case_investigation_builds_correct_context():
    mock_agent = MockAIAgent()
    service = CaseInvestigationService(ai_agent=mock_agent)

    case = build_case()

    result = service.investigate(case)

    assert result["investigation_status"] == "COMPLETED"
    assert result["source_ip"] == "192.168.1.80"

    assert mock_agent.received_incident["incident_id"] == (
        "INC-20260917140003"
    )
    assert mock_agent.received_incident["case_id"] == "CASE-12345678"
    assert mock_agent.received_incident["type"] == "Credential Theft Activity"
    assert mock_agent.received_incident["risk"] == "CRITICAL"
    assert mock_agent.received_incident["source_ip"] == "192.168.1.80"


def test_case_investigation_preserves_evidence():
    mock_agent = MockAIAgent()
    service = CaseInvestigationService(ai_agent=mock_agent)

    case = build_case()

    service.investigate(case)

    evidence = mock_agent.received_incident["evidence"]

    assert len(evidence) == 2
    assert evidence[0]["evidence_type"] == "SOURCE_IP"
    assert evidence[0]["value"] == "192.168.1.80"
    assert evidence[1]["evidence_type"] == "MITRE_TECHNIQUE"
    assert evidence[1]["value"] == "T1110"


def test_source_ip_evidence_takes_priority_over_ioc():
    mock_agent = MockAIAgent()
    service = CaseInvestigationService(ai_agent=mock_agent)

    case = build_case(source_ip_in_ioc=True)

    service.investigate(case)

    assert mock_agent.received_incident["source_ip"] == "192.168.1.80"


def test_case_investigation_requires_case():
    mock_agent = MockAIAgent()
    service = CaseInvestigationService(ai_agent=mock_agent)

    try:
        service.investigate(None)
        assert False, "Expected ValueError"
    except ValueError as error:
        assert str(error) == "Case is required"