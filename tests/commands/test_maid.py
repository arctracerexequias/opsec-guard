"""Tests for MAID info commands."""
import pytest
from typer.testing import CliRunner
from opsec_guard.commands.maid import app

runner = CliRunner()


def test_maid_info():
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "MAID" in result.output
    assert "GAID" in result.output
    assert "IDFA" in result.output


def test_maid_info_mentions_rtb():
    result = runner.invoke(app, ["info"])
    assert "Real-Time Bidding" in result.output or "RTB" in result.output


def test_maid_info_mentions_ph():
    result = runner.invoke(app, ["info"])
    assert "Le Monde" in result.output or "Philippines" in result.output or "French" in result.output


def test_maid_reset():
    result = runner.invoke(app, ["reset"])
    assert result.exit_code == 0
    assert "Android" in result.output
    assert "iOS" in result.output
    assert "Reset advertising ID" in result.output


def test_maid_reset_executive_schedule():
    result = runner.invoke(app, ["reset"])
    assert "executive" in result.output.lower() or "Executive" in result.output


def test_techniques_list():
    result = runner.invoke(app, ["techniques"])
    assert result.exit_code == 0
    assert "Real-Time Bidding" in result.output
    assert "Geofencing" in result.output
    assert "Pattern-of-Life" in result.output


def test_techniques_specific_rtb():
    result = runner.invoke(app, ["techniques", "rtb"])
    assert result.exit_code == 0
    assert "Real-Time Bidding" in result.output
    assert "200-500" in result.output


def test_techniques_specific_geofencing():
    result = runner.invoke(app, ["techniques", "geofencing"])
    assert result.exit_code == 0
    assert "Geofencing" in result.output
    assert "5-50" in result.output


def test_techniques_unknown():
    result = runner.invoke(app, ["techniques", "made_up_technique"])
    assert result.exit_code == 0
    assert "not found" in result.output.lower() or "Available" in result.output


def test_techniques_zero_click():
    result = runner.invoke(app, ["techniques", "zero_click_malware"])
    assert result.exit_code == 0
    assert "Pegasus" in result.output or "malware" in result.output.lower()
