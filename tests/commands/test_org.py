"""Tests for org compliance commands."""
from typer.testing import CliRunner
from opsec_guard.commands.org import app

runner = CliRunner()


def test_policy():
    result = runner.invoke(app, ["policy"])
    assert result.exit_code == 0
    assert "Executive" in result.output
    assert "MAID" in result.output
    assert "Airplane Mode" in result.output


def test_compliance_ph_dpa():
    result = runner.invoke(app, ["compliance"])
    assert result.exit_code == 0
    assert "RA 10173" in result.output
    assert "Data Privacy Act" in result.output


def test_compliance_gdpr():
    result = runner.invoke(app, ["compliance"])
    assert "GDPR" in result.output
    assert "Art. 6" in result.output


def test_compliance_ccpa():
    result = runner.invoke(app, ["compliance"])
    assert "CCPA" in result.output


def test_compliance_iso():
    result = runner.invoke(app, ["compliance"])
    assert "ISO" in result.output or "27001" in result.output


def test_compliance_nist():
    result = runner.invoke(app, ["compliance"])
    assert "NIST" in result.output or "800-124" in result.output


def test_compliance_defensive_only_notice():
    result = runner.invoke(app, ["compliance"])
    assert "defensive" in result.output.lower() or "authorized" in result.output.lower()
