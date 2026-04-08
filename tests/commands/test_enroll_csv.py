"""Tests for CSV bulk enrollment."""
import csv
import pytest
from pathlib import Path
from typer.testing import CliRunner
from unittest.mock import patch
from opsec_guard.commands.enroll import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def temp_storage(tmp_path):
    with patch("opsec_guard.utils.storage.DATA_DIR", tmp_path), \
         patch("opsec_guard.utils.storage.PERSONNEL_FILE", tmp_path / "personnel.enc"), \
         patch("opsec_guard.utils.storage.AUDIT_FILE", tmp_path / "audits.enc"), \
         patch("opsec_guard.utils.storage.KEY_FILE", tmp_path / ".key"):
        yield tmp_path


def write_csv(tmp_path: Path, rows: list[dict], filename="test.csv") -> Path:
    path = tmp_path / filename
    if rows:
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
    return path


def test_template_prints():
    result = runner.invoke(app, ["template"])
    assert result.exit_code == 0
    assert "name" in result.output
    assert "email" in result.output
    assert "tier" in result.output
    assert "executive" in result.output


def test_template_save(tmp_path):
    out = tmp_path / "template.csv"
    result = runner.invoke(app, ["template", "--output", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    content = out.read_text()
    assert "name" in content
    assert "email" in content


def test_import_standard_users(tmp_path):
    path = write_csv(tmp_path, [
        {"name": "Alice", "email": "alice@corp.com", "role": "Staff", "tier": "standard", "platform": "android", "security_officer_email": ""},
        {"name": "Bob", "email": "bob@corp.com", "role": "Staff", "tier": "standard", "platform": "ios", "security_officer_email": ""},
    ])
    result = runner.invoke(app, ["import", str(path), "--yes"])
    assert result.exit_code == 0
    assert "2 personnel enrolled" in result.output


def test_import_executive_tier(tmp_path):
    path = write_csv(tmp_path, [
        {"name": "CEO Test", "email": "ceo@corp.com", "role": "CEO", "tier": "executive",
         "platform": "android", "security_officer_email": "cso@corp.com"},
    ])
    result = runner.invoke(app, ["import", str(path), "--yes"])
    assert result.exit_code == 0
    assert "enrolled successfully" in result.output
    # Verify stored correctly
    from opsec_guard.utils.storage import load_personnel
    records = load_personnel()
    assert any(r["tier"] == "executive" and r["name"] == "CEO Test" for r in records)


def test_import_dry_run(tmp_path):
    path = write_csv(tmp_path, [
        {"name": "Test User", "email": "test@corp.com", "tier": "standard", "platform": "android"},
    ])
    result = runner.invoke(app, ["import", str(path), "--yes", "--dry-run"])
    assert result.exit_code == 0
    assert "Dry run" in result.output
    # Nothing should be saved
    from opsec_guard.utils.storage import load_personnel
    assert load_personnel() == []


def test_import_missing_required_columns(tmp_path):
    path = write_csv(tmp_path, [{"role": "Staff", "tier": "standard"}])
    result = runner.invoke(app, ["import", str(path), "--yes"])
    assert result.exit_code == 1
    assert "Missing required columns" in result.output


def test_import_invalid_email(tmp_path):
    path = write_csv(tmp_path, [
        {"name": "Bad Email", "email": "notanemail", "tier": "standard"},
    ])
    result = runner.invoke(app, ["import", str(path), "--yes"])
    assert result.exit_code == 0
    assert "Invalid email" in result.output
    assert "0 to enroll" in result.output or "Nothing to enroll" in result.output


def test_import_skip_existing(tmp_path):
    from opsec_guard.utils.storage import enroll_personnel
    enroll_personnel({"id": "AAA111", "name": "Existing", "email": "exist@corp.com",
                      "tier": "standard", "platform": "android", "consent_given": True})

    path = write_csv(tmp_path, [
        {"name": "Existing", "email": "exist@corp.com", "tier": "standard", "platform": "android"},
        {"name": "New Person", "email": "new@corp.com", "tier": "standard", "platform": "android"},
    ])
    result = runner.invoke(app, ["import", str(path), "--yes", "--skip-existing"])
    assert result.exit_code == 0
    assert "already enrolled" in result.output  # appears in summary line
    assert "1 personnel enrolled" in result.output


def test_import_file_not_found():
    result = runner.invoke(app, ["import", "/nonexistent/file.csv", "--yes"])
    assert result.exit_code == 1
    assert "not found" in result.output.lower()


def test_import_mixed_tiers(tmp_path):
    path = write_csv(tmp_path, [
        {"name": "Exec One", "email": "e1@corp.com", "tier": "executive", "platform": "android", "security_officer_email": "cso@corp.com"},
        {"name": "Staff One", "email": "s1@corp.com", "tier": "standard", "platform": "android"},
        {"name": "Staff Two", "email": "s2@corp.com", "tier": "standard", "platform": "ios"},
    ])
    result = runner.invoke(app, ["import", str(path), "--yes"])
    assert result.exit_code == 0
    assert "3 personnel enrolled" in result.output
    from opsec_guard.utils.storage import load_personnel
    records = load_personnel()
    assert len(records) == 3
    tiers = {r["tier"] for r in records}
    assert "executive" in tiers
    assert "standard" in tiers


def test_export_after_import(tmp_path):
    path = write_csv(tmp_path, [
        {"name": "Export Test", "email": "exp@corp.com", "tier": "standard", "platform": "android"},
    ])
    runner.invoke(app, ["import", str(path), "--yes"])

    result = runner.invoke(app, ["export"])
    assert result.exit_code == 0
    assert "Export Test" in result.output
    assert "exp@corp.com" in result.output


def test_export_to_file(tmp_path):
    path = write_csv(tmp_path, [
        {"name": "Save Test", "email": "save@corp.com", "tier": "standard", "platform": "android"},
    ])
    runner.invoke(app, ["import", str(path), "--yes"])

    out = tmp_path / "export.csv"
    result = runner.invoke(app, ["export", "--output", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    content = out.read_text()
    assert "Save Test" in content


def test_import_utf8_bom(tmp_path):
    """CSV files saved from Excel often have UTF-8 BOM."""
    path = tmp_path / "excel.csv"
    path.write_bytes(
        b"\xef\xbb\xbfname,email,tier,platform\r\n"
        b"Excel User,excel@corp.com,standard,android\r\n"
    )
    result = runner.invoke(app, ["import", str(path), "--yes"])
    assert result.exit_code == 0
    assert "1 personnel enrolled" in result.output
