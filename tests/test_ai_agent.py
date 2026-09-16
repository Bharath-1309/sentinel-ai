import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.ai_agent import AISOCAgent


def test_ai_agent_creates_investigation_request():

    agent = AISOCAgent()

    incident = {
        "incident_id": "INC-20260915102109",
        "type": "Potential Account Compromise",
        "risk": "CRITICAL",
        "source_ip": "192.168.1.50"
    }

    result = agent.investigate(incident)

    assert result["incident_id"] == "INC-20260915102109"
    assert result["type"] == "Potential Account Compromise"
    assert result["risk"] == "CRITICAL"
    assert result["source_ip"] == "192.168.1.50"
    assert result["investigation_status"] == "PENDING"
    assert result["analysis"] is None
    assert result["recommendations"] == []