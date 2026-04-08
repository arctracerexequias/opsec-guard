"""Tests for AppRiskProfile merge logic."""
import pytest
from opsec_guard.sources.base import AppRiskProfile


def make_profile(**kwargs):
    defaults = dict(
        app_name="TestApp",
        package_id="com.test.app",
        platform="android",
    )
    return AppRiskProfile(**{**defaults, **kwargs})


def test_merge_prefers_self_non_none():
    a = make_profile(collects_maid=True, risk_score=80)
    b = make_profile(collects_maid=False, risk_score=None)
    merged = a.merge(b)
    assert merged.collects_maid is True
    assert merged.risk_score == 80


def test_merge_falls_back_to_other():
    a = make_profile(collects_maid=None, risk_score=None)
    b = make_profile(collects_maid=True, risk_score=60)
    merged = a.merge(b)
    assert merged.collects_maid is True
    assert merged.risk_score == 60


def test_merge_combines_sdks():
    a = make_profile(sdks=["Adjust", "Firebase"])
    b = make_profile(sdks=["AppsFlyer", "Firebase"])
    merged = a.merge(b)
    assert "Adjust" in merged.sdks
    assert "AppsFlyer" in merged.sdks
    assert merged.sdks.count("Firebase") == 1  # deduped


def test_merge_combines_brokers():
    a = make_profile(brokers=["Oracle", "Meta"])
    b = make_profile(brokers=["Criteo", "Meta"])
    merged = a.merge(b)
    assert "Oracle" in merged.brokers
    assert "Criteo" in merged.brokers
    assert merged.brokers.count("Meta") == 1


def test_merge_source_combined():
    a = make_profile(source="exodus")
    b = make_profile(source="google_play")
    merged = a.merge(b)
    assert "exodus" in merged.source
    assert "google_play" in merged.source


def test_merge_app_name_from_self():
    a = make_profile(app_name="TikTok")
    b = make_profile(app_name="TikTok (alternate)")
    merged = a.merge(b)
    assert merged.app_name == "TikTok"


def test_merge_raw_dict_merged():
    a = make_profile(raw={"key_a": 1})
    b = make_profile(raw={"key_b": 2})
    merged = a.merge(b)
    assert "key_a" in merged.raw
    assert "key_b" in merged.raw
