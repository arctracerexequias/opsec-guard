import pytest
from unittest.mock import patch, MagicMock
from opsec_guard.sources.base import AppRiskProfile, _dedup
from opsec_guard.sources.exodus import ExodusSource, _profile_from_report, _is_maid_tracker
from opsec_guard.sources.app_store import AppStoreSource, _build_profile as _ios_build
from opsec_guard.sources.google_play import GooglePlaySource
from opsec_guard.sources.manager import fetch_all, source_status
from opsec_guard.utils.cache import get as cache_get, set as cache_set, clear_all


# ---------------------------------------------------------------------------
# AppRiskProfile
# ---------------------------------------------------------------------------

def test_profile_merge_trackers():
    a = AppRiskProfile(name="App", trackers=["AdMob"])
    b = AppRiskProfile(name="App", trackers=["AppLovin", "AdMob"])
    a.merge(b)
    assert "AdMob" in a.trackers
    assert "AppLovin" in a.trackers
    assert a.trackers.count("AdMob") == 1  # deduped


def test_profile_merge_maid_risk_true_wins():
    a = AppRiskProfile(name="App", maid_risk=False)
    b = AppRiskProfile(name="App", maid_risk=True)
    a.merge(b)
    assert a.maid_risk is True


def test_profile_merge_maid_risk_false_no_overwrite():
    a = AppRiskProfile(name="App", maid_risk=True)
    b = AppRiskProfile(name="App", maid_risk=False)
    a.merge(b)
    assert a.maid_risk is True


def test_profile_compute_risk_critical():
    p = AppRiskProfile(name="App", maid_risk=True,
                       maid_trackers=["X-Mode", "Cuebiq", "Foursquare"],
                       permissions=["ACCESS_BACKGROUND_LOCATION"])
    p.compute_risk_level()
    assert p.risk_level == "critical"


def test_profile_compute_risk_unknown():
    p = AppRiskProfile(name="App")
    p.compute_risk_level()
    assert p.risk_level == "unknown"


def test_dedup_preserves_order():
    result = _dedup(["b", "a", "b", "c", "a"])
    assert result == ["b", "a", "c"]


def test_profile_to_dict_keys():
    p = AppRiskProfile(name="Test", package="com.test", risk_level="high")
    d = p.to_dict()
    assert "name" in d
    assert "package" in d
    assert "risk_level" in d
    assert "maid_risk" in d
    assert "sources_checked" in d


# ---------------------------------------------------------------------------
# Exodus
# ---------------------------------------------------------------------------

def test_is_maid_tracker_admob():
    assert _is_maid_tracker("Google AdMob") is True


def test_is_maid_tracker_unknown():
    assert _is_maid_tracker("SomeBenignLibrary") is False


def test_exodus_profile_from_report_trackers():
    report_data = {
        "reports": [{
            "trackers": [
                {"name": "Google AdMob"},
                {"name": "Adjust"},
                {"name": "CoolLibrary"},
            ],
            "permissions": ["android.permission.ACCESS_FINE_LOCATION"],
        }]
    }
    profile = _profile_from_report("MyApp", "com.myapp", report_data)
    assert "Google AdMob" in profile.maid_trackers
    assert "Adjust" in profile.maid_trackers
    assert profile.maid_risk is True
    assert "exodus" in profile.sources_hit


def test_exodus_profile_no_trackers():
    report_data = {"reports": [{"trackers": [], "permissions": []}]}
    profile = _profile_from_report("CleanApp", "com.cleanapp", report_data)
    assert profile.maid_risk is False
    assert profile.maid_trackers == []


def test_exodus_profile_background_location_finding():
    report_data = {
        "reports": [{
            "trackers": [],
            "permissions": ["android.permission.ACCESS_BACKGROUND_LOCATION"],
        }]
    }
    profile = _profile_from_report("App", "com.app", report_data)
    assert any("background" in f.lower() for f in profile.findings)


def test_exodus_source_unavailable_returns_none(monkeypatch):
    src = ExodusSource()
    monkeypatch.setattr("requests.get", lambda *a, **kw: (_ for _ in ()).throw(
        __import__("requests").exceptions.ConnectionError("offline")))
    result = src.fetch("com.some.app")
    assert result is None


# ---------------------------------------------------------------------------
# App Store
# ---------------------------------------------------------------------------

def test_app_store_build_profile_with_tracking():
    data = {
        "trackId": 123456,
        "trackName": "Weather App",
        "bundleId": "com.example.weather",
        "sellerName": "ExampleCo",
        "primaryGenreName": "Weather",
        "userRatingCount": 10000,
        "privacyDetails": {
            "privacyTypes": [
                {
                    "privacyType": "DATA_USED_TO_TRACK_YOU",
                    "dataCategories": [
                        {"dataType": "Advertising Data"},
                        {"dataType": "Precise Location"},
                    ]
                }
            ]
        }
    }
    profile = _ios_build(data)
    assert profile.maid_risk is True
    assert profile.platform == "ios"
    assert any("track" in f.lower() for f in profile.findings)


def test_app_store_build_profile_clean():
    data = {
        "trackId": 999,
        "trackName": "Calculator",
        "bundleId": "com.example.calc",
        "sellerName": "DevCo",
        "primaryGenreName": "Utilities",
        "userRatingCount": 500,
        "privacyDetails": {"privacyTypes": []}
    }
    profile = _ios_build(data)
    assert profile.maid_risk is None or profile.maid_risk is False
    assert profile.platform == "ios"


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def test_cache_set_and_get():
    clear_all()
    cache_set("test_source", "testkey", {"foo": "bar"})
    result = cache_get("test_source", "testkey")
    assert result == {"foo": "bar"}


def test_cache_miss_returns_none():
    result = cache_get("test_source", "nonexistent_key_xyz")
    assert result is None


def test_cache_clear():
    cache_set("test_source", "key1", {"x": 1})
    cache_set("test_source", "key2", {"x": 2})
    count = clear_all()
    assert count >= 2


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

def test_source_status_returns_list():
    statuses = source_status()
    assert isinstance(statuses, list)
    assert len(statuses) == 4
    names = [s["name"] for s in statuses]
    assert "exodus" in names
    assert "google_play" in names
    assert "app_store" in names
    assert "appcensus" in names


def test_fetch_all_returns_profile():
    # Mock all sources to return None (unavailable) — should still return a profile
    with patch("opsec_guard.sources.manager.ALL_SOURCES", []):
        profile = fetch_all("com.test.app")
    assert isinstance(profile, AppRiskProfile)
    assert profile.name == "com.test.app"


def test_fetch_all_merges_sources():
    from opsec_guard.sources.base import BaseSource

    class FakeSource(BaseSource):
        name = "fake"
        platform = "android"
        def fetch(self, query):
            return AppRiskProfile(
                name="FakeApp",
                maid_risk=True,
                trackers=["FakeSDK"],
                findings=["Fake finding"],
                sources_hit=["fake"],
            )

    with patch("opsec_guard.sources.manager.ALL_SOURCES", [FakeSource()]):
        profile = fetch_all("fakeapp")

    assert profile.maid_risk is True
    assert "FakeSDK" in profile.trackers
    assert any("Fake finding" in f for f in profile.findings)
