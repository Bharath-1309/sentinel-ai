from datetime import datetime
from fastapi.testclient import TestClient

import api


client = TestClient(api.app)


def mock_analysis_result():
    timestamp = datetime(2026, 9, 15, 10, 21, 9)

    mitre = {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access"
    }

    threat_intelligence = {
        "ip": "192.168.1.50",
        "malicious": False,
        "threat": None,
        "confidence": 0,
        "source": "AbuseIPDB"
    }

    alert = {
        "type": "SSH Brute Force",
        "timestamp": timestamp,
        "username": "admin",
        "ip": "192.168.1.50",
        "failed_attempts": 3,
        "successful_login": True,
        "risk": "CRITICAL",
        "mitre": mitre,
        "targeted_users": None,
        "threat_intelligence": threat_intelligence
    }

    incident = {
        "incident_id": "INC-20260915102109",
        "type": "Potential Account Compromise",
        "source_ip": "192.168.1.50",
        "risk": "CRITICAL",
        "risk_score": 90,
        "status": "OPEN",
        "alert_count": 1,
        "start_time": timestamp,
        "end_time": timestamp,
        "mitre_techniques": [mitre],
        "evidence": [alert],
        "ai_investigation": {
            "incident_id": "INC-20260915102109",
            "type": "Potential Account Compromise",
            "risk": "CRITICAL",
            "source_ip": "192.168.1.50",
            "investigation_status": "UNAVAILABLE",
            "analysis": "Gemini investigation unavailable because the API quota has been exceeded.",
            "recommendations": []
        },
        "response_playbook": {
            "incident_id": "INC-20260915102109",
            "incident_type": "Potential Account Compromise",
            "severity": "CRITICAL",
            "actions": [
                "Investigate the incident",
                "Review related security logs",
                "Identify affected systems",
                "Preserve relevant evidence",
                "Monitor for additional suspicious activity"
            ]
        }
    }

    return {
        "alerts": [alert],
        "incidents": [incident]
    }


def test_analyze_endpoint_returns_analysis(monkeypatch):

    monkeypatch.setattr(
        api,
        "analyze_logs",
        lambda: mock_analysis_result()
    )

    response = client.get("/analyze")

    assert response.status_code == 200

    data = response.json()

    assert "alerts" in data
    assert "incidents" in data

    assert len(data["alerts"]) == 1
    assert len(data["incidents"]) == 1


def test_incident_contains_response_playbook(monkeypatch):

    monkeypatch.setattr(
        api,
        "analyze_logs",
        lambda: mock_analysis_result()
    )

    response = client.get("/analyze")

    assert response.status_code == 200

    incident = response.json()["incidents"][0]

    assert incident["response_playbook"] is not None

    playbook = incident["response_playbook"]

    assert playbook["incident_id"] == "INC-20260915102109"
    assert playbook["incident_type"] == "Potential Account Compromise"
    assert playbook["severity"] == "CRITICAL"

    assert isinstance(playbook["actions"], list)
    assert len(playbook["actions"]) > 0

def test_incidents_endpoint_returns_stored_incidents(monkeypatch):
    stored_incidents = [
        {
            "incident_id": "INC-TEST-001",
            "incident_type": "Credential Theft Activity",
            "source_ip": "192.168.1.80",
            "risk": "CRITICAL",
            "risk_score": 80,
            "status": "OPEN",
            "alert_count": 1,
            "start_time": "2026-09-17T14:00:03",
            "end_time": "2026-09-17T14:00:03"
        }
    ]

    monkeypatch.setattr(api, "get_incidents", lambda: stored_incidents)

    response = client.get("/incidents")

    assert response.status_code == 200

    data = response.json()

    assert "incidents" in data
    assert len(data["incidents"]) == 1

    incident = data["incidents"][0]

    assert incident["incident_id"] == "INC-TEST-001"
    assert incident["incident_type"] == "Credential Theft Activity"
    assert incident["risk"] == "CRITICAL"
    assert incident["risk_score"] == 80

def test_hunting_api_rejects_invalid_limit():
    response = client.post(
        "/hunting/search",
        json={
            "query": {
                "field": "username",
                "operator": "equals",
                "value": "root"
            },
            "limit": 0
        }
    )

    assert response.status_code == 422


def test_hunting_api_rejects_limit_above_maximum():
    response = client.post(
        "/hunting/search",
        json={
            "query": {
                "field": "username",
                "operator": "equals",
                "value": "root"
            },
            "limit": 1001
        }
    )

    assert response.status_code == 422


def test_hunting_api_rejects_invalid_sort_order():
    response = client.post(
        "/hunting/search",
        json={
            "query": {
                "field": "username",
                "operator": "equals",
                "value": "root"
            },
            "sort_order": "invalid"
        }
    )

    assert response.status_code == 422


def test_hunting_api_rejects_unknown_field():
    response = client.post(
        "/hunting/search",
        json={
            "query": {
                "field": "unknown_field",
                "operator": "equals",
                "value": "root"
            }
        }
    )

    assert response.status_code == 422


def test_hunting_api_rejects_unknown_operator():
    response = client.post(
        "/hunting/search",
        json={
            "query": {
                "field": "username",
                "operator": "invalid_operator",
                "value": "root"
            }
        }
    )

    assert response.status_code == 422


def test_hunting_api_rejects_invalid_time_range():
    response = client.post(
        "/hunting/search",
        json={
            "time_range": {
                "start": "2026-09-15T12:00:00",
                "end": "2026-09-15T11:00:00"
            }
        }
    )

    assert response.status_code == 422


def test_hunting_api_rejects_invalid_logic():
    response = client.post(
        "/hunting/search",
        json={
            "query_group": {
                "queries": [
                    {
                        "field": "username",
                        "operator": "equals",
                        "value": "root"
                    }
                ],
                "logic": "INVALID"
            }
        }
    )

    assert response.status_code == 422


def test_hunting_api_rejects_empty_query_group():
    response = client.post(
        "/hunting/search",
        json={
            "query_group": {
                "queries": [],
                "logic": "AND"
            }
        }
    )

    assert response.status_code == 422    