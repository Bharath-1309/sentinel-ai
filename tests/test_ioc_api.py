from fastapi.testclient import TestClient

from api import app


client = TestClient(app)


def test_enrich_ioc_api():
    response = client.post(
        "/ioc/enrich",
        json={"value": "example.com"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["value"] == "example.com"
    assert data["ioc_type"] == "domain"
    assert data["valid"] is True
    assert data["enriched"] is False


def test_invalid_ioc_api():
    response = client.post(
        "/ioc/enrich",
        json={"value": "definitely-invalid"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["valid"] is False
    assert data["ioc_type"] is None


def test_list_iocs_api():
    client.post(
        "/ioc/enrich",
        json={"value": "example.com"},
    )

    response = client.get("/ioc")

    assert response.status_code == 200

    data = response.json()

    assert "count" in data
    assert "iocs" in data


def test_get_existing_ioc_api():
    client.post(
        "/ioc/enrich",
        json={"value": "example.com"},
    )

    response = client.get("/ioc/example.com")

    assert response.status_code == 200

    data = response.json()

    assert data["value"] == "example.com"
    assert data["ioc_type"] == "domain"


def test_get_existing_ip_ioc_api():
    response = client.post(
        "/ioc/enrich",
        json={"value": "8.8.8.8"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["valid"] is True
    assert data["enriched"] is True

    result = data["result"]

    assert result["malicious"] is False
    assert "confidence" in result
    assert "source" in result
    assert "tags" in result
    assert "provider_results" in result


def test_get_ip_ioc_provider_evidence():
    client.post(
        "/ioc/enrich",
        json={"value": "8.8.8.8"},
    )

    response = client.get("/ioc/8.8.8.8")

    assert response.status_code == 200

    data = response.json()

    assert data["ioc_type"] == "ip"
    assert data["result"] is not None
    assert "provider_results" in data["result"]


def test_get_missing_ioc_api():
    response = client.get("/ioc/not-real.example")

    assert response.status_code == 404


def test_delete_ioc_api():
    client.post(
        "/ioc/enrich",
        json={"value": "delete-me.example"},
    )

    response = client.delete("/ioc/delete-me.example")

    assert response.status_code == 200
    assert response.json()["value"] == "delete-me.example"


def test_delete_missing_ioc_api():
    response = client.delete("/ioc/not-real.example")

    assert response.status_code == 404