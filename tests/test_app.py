"""Tests for the Stage 1 Flask API."""
import pytest

from app import create_app
from scanner.target_validator import ConnectivityResult, TargetPolicy


@pytest.fixture
def client(fake_dns):
    app = create_app(policy=TargetPolicy(request_delay=0))
    app.config["TESTING"] = True
    return app.test_client()


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_validate_requires_json_body(client):
    assert client.post("/api/validate", data="nope").status_code == 400
    assert client.post("/api/validate", json={}).status_code == 400


def test_validate_requires_authorization(client):
    response = client.post("/api/validate", json={"url": "https://example.com"})
    assert response.status_code == 400
    assert "Authorization" in response.get_json()["validation"]["error"]


def test_validate_rejects_internal_target(client):
    response = client.post("/api/validate", json={"url": "http://127.0.0.1", "authorized": True})
    assert response.status_code == 400


def test_validate_accepts_public_target(client):
    response = client.post("/api/validate", json={"url": "example.com", "authorized": True})
    assert response.status_code == 200
    assert response.get_json()["validation"]["url"] == "https://example.com/"
    assert "connectivity" not in response.get_json()


def test_validate_with_connectivity(client, monkeypatch):
    monkeypatch.setattr(
        "app.check_connectivity",
        lambda url, policy: ConnectivityResult(reachable=True, final_url=url, status_code=200),
    )
    response = client.post(
        "/api/validate",
        json={"url": "example.com", "authorized": True, "check_connectivity": True},
    )
    assert response.status_code == 200
    assert response.get_json()["connectivity"]["status_code"] == 200
