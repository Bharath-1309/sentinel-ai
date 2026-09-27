from analyzer.response_engine import ResponseEngine


def test_credential_theft_playbook():

    engine = ResponseEngine()

    incident = {
        "incident_id": "INC-001",
        "type": "Credential Theft Activity",
        "risk": "CRITICAL"
    }

    playbook = engine.generate_playbook(incident)

    assert playbook["incident_id"] == "INC-001"
    assert playbook["incident_type"] == "Credential Theft Activity"
    assert playbook["severity"] == "CRITICAL"

    assert "Isolate the affected endpoint" in playbook["actions"]
    assert "Reset potentially compromised credentials" in playbook["actions"]


def test_network_reconnaissance_playbook():

    engine = ResponseEngine()

    incident = {
        "incident_id": "INC-002",
        "type": "Network Reconnaissance",
        "risk": "HIGH"
    }

    playbook = engine.generate_playbook(incident)

    assert playbook["severity"] == "HIGH"
    assert "Investigate the scanning source IP" in playbook["actions"]


def test_unknown_incident_gets_default_playbook():

    engine = ResponseEngine()

    incident = {
        "incident_id": "INC-003",
        "type": "Unknown Incident",
        "risk": "MEDIUM"
    }

    playbook = engine.generate_playbook(incident)

    assert playbook["severity"] == "MEDIUM"
    assert len(playbook["actions"]) > 0