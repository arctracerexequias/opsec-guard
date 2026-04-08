"""Tests for check commands — local DB lookups."""
import pytest
from typer.testing import CliRunner
from opsec_guard.commands.check import app

runner = CliRunner()


def test_check_tiktok():
    result = runner.invoke(app, ["app", "TikTok"])
    assert result.exit_code == 0
    assert "TikTok" in result.output
    assert "Risk Score" in result.output


def test_check_tiktok_risk_fields():
    result = runner.invoke(app, ["app", "TikTok"])
    assert "Collects MAID" in result.output
    assert "Background Location" in result.output


def test_check_facebook():
    result = runner.invoke(app, ["app", "Facebook"])
    assert result.exit_code == 0
    assert "Facebook" in result.output


def test_check_gcash():
    result = runner.invoke(app, ["app", "GCash"])
    assert result.exit_code == 0
    assert "GCash" in result.output


def test_check_unknown_app():
    result = runner.invoke(app, ["app", "ThisAppDoesNotExist12345"])
    assert result.exit_code == 0
    assert "not in local database" in result.output.lower() or "not found" in result.output.lower()


def test_check_broker_fog():
    result = runner.invoke(app, ["broker", "Fog"])
    assert result.exit_code == 0
    assert "Fog" in result.output
    assert "Critical" in result.output


def test_check_broker_babel():
    result = runner.invoke(app, ["broker", "Babel"])
    assert result.exit_code == 0
    assert "Babel" in result.output


def test_check_broker_oracle():
    result = runner.invoke(app, ["broker", "Oracle"])
    assert result.exit_code == 0
    assert "Oracle" in result.output
    assert "opt_out_url" in result.output or "datacloudoptout" in result.output


def test_check_broker_not_found():
    result = runner.invoke(app, ["broker", "XXXXUNKNOWN"])
    assert result.exit_code == 0
    assert "not found" in result.output.lower()


def test_check_muslim_pro():
    result = runner.invoke(app, ["app", "Muslim Pro"])
    assert result.exit_code == 0
    assert "Muslim Pro" in result.output
    assert "Critical" in result.output or "95" in result.output
