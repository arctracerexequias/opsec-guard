"""Tests for geolocation utilities."""
import pytest
from opsec_guard.utils.geo import haversine_meters, check_flagged_locations, is_in_flagged_zone


def test_haversine_same_point():
    assert haversine_meters(14.5547, 121.0244, 14.5547, 121.0244) == 0.0


def test_haversine_known_distance():
    # Makati to BGC is approx 2.5km
    dist = haversine_meters(14.5547, 121.0244, 14.5515, 121.0476)
    assert 2000 < dist < 3000


def test_check_flagged_makati():
    # Makati CBD center — should be in flagged zone
    results = check_flagged_locations(14.5547, 121.0244)
    names = [r["name"] for r in results]
    assert any("Makati" in n for n in names)


def test_check_flagged_naia():
    # NAIA terminal — should be flagged
    results = check_flagged_locations(14.5086, 121.0197)
    names = [r["name"] for r in results]
    assert any("NAIA" in n for n in names)


def test_check_flagged_no_match():
    # Middle of Pacific Ocean — no flags
    results = check_flagged_locations(0.0, 160.0)
    assert results == []


def test_is_in_flagged_zone_true():
    # Malacanang Palace coordinates
    assert is_in_flagged_zone(14.5958, 120.9930) is True


def test_is_in_flagged_zone_false():
    assert is_in_flagged_zone(0.0, 0.0) is False


def test_flagged_result_has_distance():
    results = check_flagged_locations(14.5547, 121.0244)
    for r in results:
        assert "distance_meters" in r
        assert r["distance_meters"] >= 0


def test_critical_location_malacanang():
    results = check_flagged_locations(14.5958, 120.9930)
    critical = [r for r in results if r["risk_level"] == "Critical"]
    assert len(critical) > 0
