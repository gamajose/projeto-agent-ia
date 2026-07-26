from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_exposes_safe_operational_defaults():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == "1.2.2"
    assert body["default_mode"] == "propose"
    assert body["strict_host_key_checking"] is True


def test_checkmk_webhook_requires_configured_token():
    response = client.post(
        "/webhooks/checkmk",
        json={"host": "192.0.2.10", "service": "Systemd Socket Summary", "state": "CRITICAL", "output": "1 failed socket"},
    )
    assert response.status_code in {401, 503}


def test_investigation_api_requires_token():
    response = client.get("/api/investigations/11111111-1111-1111-1111-111111111111")
    assert response.status_code in {401, 503}
