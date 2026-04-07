import pytest
from opsec_guard.commands.check import _fuzzy_match, _load_db


def test_fuzzy_match_exact():
    assert _fuzzy_match("strava", "Strava") is True


def test_fuzzy_match_partial():
    assert _fuzzy_match("weather", "The Weather Channel") is True


def test_fuzzy_match_package():
    assert _fuzzy_match("com.strava", "com.strava") is True


def test_fuzzy_match_no_match():
    assert _fuzzy_match("unknownapp12345", "The Weather Channel") is False


def test_load_db_returns_data():
    apps, sdks, brokers = _load_db()
    assert len(apps) > 0
    assert len(sdks) > 0
    assert len(brokers) > 0


def test_all_apps_have_required_fields():
    apps, _, _ = _load_db()
    required = {"name", "package", "risk", "collects_maid", "links_maid_to_gps", "brokers"}
    for app in apps:
        assert required.issubset(app.keys()), f"App '{app.get('name')}' missing fields"


def test_all_sdks_have_required_fields():
    _, sdks, _ = _load_db()
    required = {"name", "risk", "reads_maid", "transmits_maid_gps", "rtb_participant"}
    for sdk in sdks:
        assert required.issubset(sdk.keys()), f"SDK '{sdk.get('name')}' missing fields"


def test_all_brokers_have_required_fields():
    _, _, brokers = _load_db()
    required = {"name", "risk", "data_types", "known_clients", "incident"}
    for broker in brokers:
        assert required.issubset(broker.keys()), f"Broker '{broker.get('name')}' missing fields"


def test_risk_levels_are_valid():
    apps, sdks, brokers = _load_db()
    valid = {"critical", "high", "medium", "low"}
    for entry in apps + sdks + brokers:
        assert entry["risk"] in valid, f"Invalid risk level in '{entry.get('name')}'"


def test_critical_apps_present():
    apps, _, _ = _load_db()
    critical = [a for a in apps if a["risk"] == "critical"]
    assert len(critical) >= 2, "Expected at least 2 critical-risk apps"


def test_known_app_strava_found():
    apps, _, _ = _load_db()
    names = [a["name"].lower() for a in apps]
    assert any("strava" in n for n in names)


def test_known_sdk_xmode_found():
    _, sdks, _ = _load_db()
    names = [s["name"].lower() for s in sdks]
    assert any("x-mode" in n or "outlogic" in n for n in names)


def test_known_broker_babel_street_found():
    _, _, brokers = _load_db()
    names = [b["name"].lower() for b in brokers]
    assert any("babel" in n for n in names)
