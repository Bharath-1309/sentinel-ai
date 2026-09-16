import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.ai_agent import AISOCAgent


def test_ai_agent_creates_investigation_request(monkeypatch):

    agent = AISOCAgent()

    incident = {
        "incident_id": "INC-20260915102109",
        "type": "Potential Account Compromise",
        "risk": "CRITICAL",
        "source_ip": "192.168.1.50"
    }

    def mock_post(*args, **kwargs):

        class MockResponse:
            status_code = 200

            def json(self):
                return {
                    "candidates": [
                        {
                            "content": {
                                "parts": [
                                    {
                                        "text": (
                                            "ANALYSIS:\n"
                                            "The incident requires immediate investigation.\n\n"
                                            "RECOMMENDATIONS:\n"
                                            "- Review the affected account activity.\n"
                                            "- Validate the source IP against security logs.\n"
                                            "- Check for additional authentication events."
                                        )
                                    }
                                ]
                            }
                        }
                    ]
                }

        return MockResponse()

    monkeypatch.setattr(
        "analyzer.ai_agent.requests.post",
        mock_post
    )

    result = agent.investigate(incident)

    assert result["incident_id"] == "INC-20260915102109"
    assert result["type"] == "Potential Account Compromise"
    assert result["risk"] == "CRITICAL"
    assert result["source_ip"] == "192.168.1.50"
    assert result["investigation_status"] == "COMPLETED"
    assert result["analysis"] is not None
    assert len(result["recommendations"]) == 3


def test_ai_agent_generates_critical_recommendations(monkeypatch):

    agent = AISOCAgent()

    incident = {
        "incident_id": "INC-CRITICAL-001",
        "type": "Potential Account Compromise",
        "risk": "CRITICAL",
        "source_ip": "192.168.1.50"
    }

    def mock_post(*args, **kwargs):

        class MockResponse:
            status_code = 200

            def json(self):
                return {
                    "candidates": [
                        {
                            "content": {
                                "parts": [
                                    {
                                        "text": (
                                            "ANALYSIS:\n"
                                            "The incident requires immediate investigation.\n\n"
                                            "RECOMMENDATIONS:\n"
                                            "- Review the affected account activity.\n"
                                            "- Check for additional successful authentication events.\n"
                                            "- Validate the source IP against security logs."
                                        )
                                    }
                                ]
                            }
                        }
                    ]
                }

        return MockResponse()

    monkeypatch.setattr(
        "analyzer.ai_agent.requests.post",
        mock_post
    )

    result = agent.investigate(incident)

    assert result["investigation_status"] == "COMPLETED"

    assert (
        "immediate investigation"
        in result["analysis"]
    )

    assert (
        "Review the affected account activity."
        in result["recommendations"]
    )

    assert (
        "Check for additional successful authentication events."
        in result["recommendations"]
    )