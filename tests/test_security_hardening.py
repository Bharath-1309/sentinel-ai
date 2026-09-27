from datetime import datetime

from fastapi.testclient import TestClient

from api import app
from analyzer.hunting.engine import ThreatHuntingEngine
from analyzer.hunting.models import HuntingQuery
from analyzer.ioc_store import IOCStore
from analyzer.response_engine import ResponseEngine


client = TestClient(app)


def test_ioc_store_treats_sql_injection_as_plain_data():
    store = IOCStore()

    malicious_value = "' OR '1'='1'; DROP TABLE iocs; --"

    ioc = type(
        "TestIOC",
        (),
        {
            "value": malicious_value,
            "ioc_type": "domain",
        },
    )()

    store.add_ioc(ioc)

    assert store.get_ioc(malicious_value) is ioc
    assert len(store.list_iocs()) == 1


def test_hunting_treats_sql_injection_as_plain_search_value():
    engine = ThreatHuntingEngine()

    event = {
        "timestamp": datetime.now(),
        "source": "auth",
        "event_type": "authentication_failure",
        "username": "admin",
        "source_ip": "192.168.1.50",
        "host": "server",
        "message": "failed login",
        "raw_log": "failed login",
        "failed_attempts": 5,
    }

    malicious_value = "' OR '1'='1"

    query = HuntingQuery(
        field="username",
        operator="equals",
        value=malicious_value,
    )

    results = engine.search([event], query)

    assert results == []


def test_hunting_handles_command_injection_style_input():
    engine = ThreatHuntingEngine()

    event = {
        "timestamp": datetime.now(),
        "source": "auth",
        "event_type": "authentication_failure",
        "username": "admin; whoami",
        "source_ip": "192.168.1.50",
        "host": "server",
        "message": "failed login",
        "raw_log": "failed login",
        "failed_attempts": 1,
    }

    query = HuntingQuery(
        field="username",
        operator="equals",
        value="admin; whoami",
    )

    results = engine.search([event], query)

    assert len(results) == 1
    assert results[0]["username"] == "admin; whoami"


def test_hunting_handles_path_traversal_style_input():
    engine = ThreatHuntingEngine()

    event = {
        "timestamp": datetime.now(),
        "source": "web",
        "event_type": "request",
        "username": "../../etc/passwd",
        "source_ip": "127.0.0.1",
        "host": "server",
        "message": "request",
        "raw_log": "../../etc/passwd",
        "failed_attempts": 0,
    }

    query = HuntingQuery(
        field="username",
        operator="equals",
        value="../../etc/passwd",
    )

    results = engine.search([event], query)

    assert len(results) == 1


def test_response_engine_does_not_execute_attacker_controlled_actions():
    engine = ResponseEngine()

    incident = {
        "incident_id": "INC-SECURITY-001",
        "type": "Unknown; whoami",
        "risk": "HIGH",
    }

    result = engine.generate_playbook(incident)

    assert result["incident_id"] == "INC-SECURITY-001"
    assert result["incident_type"] == "Unknown; whoami"

    assert all(
        "whoami" not in action.lower()
        for action in result["actions"]
    )


def test_response_engine_handles_missing_optional_fields():
    engine = ResponseEngine()

    incident = {
        "incident_id": "INC-SECURITY-002",
        "type": "Unknown Incident",
        "risk": "LOW",
    }

    result = engine.generate_playbook(incident)

    assert result["incident_id"] == "INC-SECURITY-002"
    assert result["incident_type"] == "Unknown Incident"
    assert result["severity"] == "LOW"
    assert isinstance(result["actions"], list)


def test_api_rejects_invalid_json_body():
    response = client.post(
        "/phishing/analyze",
        content="{invalid-json",
        headers={
            "Content-Type": "application/json",
        },
    )

    assert response.status_code in {400, 422}


def test_ioc_api_does_not_execute_sql_injection_payload():
    payload = {
        "value": "' OR '1'='1'; DROP TABLE iocs; --",
    }

    response = client.post(
        "/ioc/enrich",
        json=payload,
    )

    assert response.status_code in {
        200,
        400,
        422,
    }


def test_api_returns_json_for_unknown_route():
    response = client.get(
        "/this-route-does-not-exist"
    )

    assert response.status_code == 404
    assert response.headers["content-type"].startswith(
        "application/json"
    )