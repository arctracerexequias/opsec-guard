"""Tests for encrypted storage."""
import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch


@pytest.fixture(autouse=True)
def temp_data_dir(tmp_path):
    with patch("opsec_guard.utils.storage.DATA_DIR", tmp_path), \
         patch("opsec_guard.utils.storage.PERSONNEL_FILE", tmp_path / "personnel.enc"), \
         patch("opsec_guard.utils.storage.AUDIT_FILE", tmp_path / "audits.enc"), \
         patch("opsec_guard.utils.storage.REPORTS_FILE", tmp_path / "device_reports.enc"), \
         patch("opsec_guard.utils.storage.KEY_FILE", tmp_path / ".key"):
        yield tmp_path


def test_enroll_and_retrieve():
    from opsec_guard.utils.storage import enroll_personnel, get_personnel
    record = {"id": "ABC123", "name": "Test User", "tier": "standard", "email": "test@test.com"}
    enroll_personnel(record)
    result = get_personnel("ABC123")
    assert result is not None
    assert result["name"] == "Test User"
    assert result["tier"] == "standard"


def test_enroll_executive_tier():
    from opsec_guard.utils.storage import enroll_personnel, get_personnel
    record = {
        "id": "EXE001",
        "name": "C-Level Exec",
        "tier": "executive",
        "email": "ceo@corp.com",
        "security_officer_email": "cso@corp.com",
    }
    enroll_personnel(record)
    result = get_personnel("EXE001")
    assert result["tier"] == "executive"
    assert result["security_officer_email"] == "cso@corp.com"


def test_update_existing_personnel():
    from opsec_guard.utils.storage import enroll_personnel, get_personnel
    record = {"id": "UPD001", "name": "Original Name", "email": "a@b.com"}
    enroll_personnel(record)
    updated = {"id": "UPD001", "name": "Updated Name", "email": "a@b.com"}
    enroll_personnel(updated)
    result = get_personnel("UPD001")
    assert result["name"] == "Updated Name"


def test_remove_personnel():
    from opsec_guard.utils.storage import enroll_personnel, remove_personnel, get_personnel
    record = {"id": "REM001", "name": "To Remove"}
    enroll_personnel(record)
    assert remove_personnel("REM001") is True
    assert get_personnel("REM001") is None


def test_remove_nonexistent():
    from opsec_guard.utils.storage import remove_personnel
    assert remove_personnel("NOPE99") is False


def test_load_personnel_empty():
    from opsec_guard.utils.storage import load_personnel
    assert load_personnel() == []


def test_save_and_load_audit():
    from opsec_guard.utils.storage import save_audit, get_audits_for_person
    audit = {"person_id": "P001", "score": 75, "answers": {"bg_location": True}}
    save_audit(audit)
    audits = get_audits_for_person("P001")
    assert len(audits) == 1
    assert audits[0]["score"] == 75


def test_save_device_report():
    from opsec_guard.utils.storage import save_device_report, load_device_reports
    report = {"person_id": "P001", "device_id": "dv-abc", "maid": "test-maid-123"}
    save_device_report(report)
    reports = load_device_reports("dv-abc")
    assert len(reports) == 1
    assert reports[0]["maid"] == "test-maid-123"


def test_latest_report_per_device():
    from opsec_guard.utils.storage import save_device_report, latest_report_per_device
    from datetime import datetime, timezone
    r1 = {"person_id": "P1", "device_id": "dv-001", "maid": "old", "received_at": "2024-01-01T00:00:00+00:00"}
    r2 = {"person_id": "P1", "device_id": "dv-001", "maid": "new", "received_at": "2024-06-01T00:00:00+00:00"}
    save_device_report(r1)
    save_device_report(r2)
    latest = latest_report_per_device()
    assert latest["dv-001"]["maid"] == "new"
