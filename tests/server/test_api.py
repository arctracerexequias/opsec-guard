"""Tests for the FastAPI monitoring server."""
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def temp_storage(tmp_path):
    with patch("opsec_guard.utils.storage.DATA_DIR", tmp_path), \
         patch("opsec_guard.utils.storage.PERSONNEL_FILE", tmp_path / "personnel.enc"), \
         patch("opsec_guard.utils.storage.AUDIT_FILE", tmp_path / "audits.enc"), \
         patch("opsec_guard.utils.storage.REPORTS_FILE", tmp_path / "device_reports.enc"), \
         patch("opsec_guard.utils.storage.KEY_FILE", tmp_path / ".key"):
        yield


@pytest.fixture
def enrolled_person(temp_storage):
    from opsec_guard.utils.storage import enroll_personnel
    enroll_personnel({
        "id": "TEST01",
        "name": "Test Person",
        "email": "test@example.com",
        "tier": "standard",
        "platform": "android",
        "active": True,
        "consent_given": True,
    })
    return "TEST01"


@pytest.fixture
def client():
    from opsec_guard.server.app import app
    return TestClient(app)


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_report_enrolled_person(client, enrolled_person):
    with patch("opsec_guard.server.app.send_executive_alert"):
        resp = client.post("/report", json={
            "person_id": "TEST01",
            "device_id": "dv-test001",
            "platform": "android",
            "maid": "test-gaid-1234",
            "risky_apps": ["com.facebook.katana"],
        })
    assert resp.status_code == 200
    assert resp.json()["status"] == "received"


def test_report_unenrolled_person(client):
    resp = client.post("/report", json={
        "person_id": "NOTFOUND",
        "device_id": "dv-001",
        "platform": "android",
    })
    assert resp.status_code == 403


def test_report_with_flagged_location(client, enrolled_person):
    with patch("opsec_guard.server.app.send_executive_alert") as mock_alert:
        # Malacañang Palace coordinates — flagged
        resp = client.post("/report", json={
            "person_id": "TEST01",
            "device_id": "dv-test001",
            "platform": "android",
            "lat": 14.5958,
            "lon": 120.9930,
        })
    assert resp.status_code == 200
    data = resp.json()
    assert data["flagged_locations"] > 0


def test_heartbeat(client, enrolled_person):
    resp = client.post("/heartbeat", json={
        "person_id": "TEST01",
        "device_id": "dv-test001",
        "battery": 85,
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_heartbeat_unenrolled(client):
    resp = client.post("/heartbeat", json={
        "person_id": "GHOST99",
        "device_id": "dv-ghost",
    })
    assert resp.status_code == 403


def test_status_empty(client):
    resp = client.get("/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "personnel" in data
    assert data["total"] == 0


def test_status_with_personnel(client, enrolled_person):
    resp = client.get("/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["personnel"][0]["id"] == "TEST01"


def test_executive_alert_on_flagged_zone(client):
    from opsec_guard.utils.storage import enroll_personnel
    enroll_personnel({
        "id": "EXEC01",
        "name": "CEO Test",
        "email": "ceo@corp.com",
        "tier": "executive",
        "security_officer_email": "cso@corp.com",
        "platform": "android",
        "active": True,
        "consent_given": True,
    })

    with patch("opsec_guard.server.app.send_executive_alert") as mock_alert:
        client.post("/report", json={
            "person_id": "EXEC01",
            "device_id": "dv-exec001",
            "platform": "android",
            "lat": 14.5958,   # Malacanang
            "lon": 120.9930,
        })
        # Alert should have been triggered for flagged zone
        mock_alert.assert_called()
