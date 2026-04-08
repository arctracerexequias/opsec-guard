"""Tests for Exodus Privacy source."""
import pytest
from unittest.mock import patch, MagicMock
from opsec_guard.sources.exodus import ExodusSource


SAMPLE_EXODUS_RESPONSE = [
    {
        "name": "TikTok",
        "updated_at": "2024-01-15",
        "reports": [
            {
                "trackers": [
                    {"name": "Google Advertising"},
                    {"name": "ByteDance SDK"},
                    {"name": "Adjust"},
                    {"name": "AppsFlyer"},
                    {"name": "Firebase Analytics"},
                    {"name": "Branch"},
                ],
                "permissions": [
                    "ACCESS_FINE_LOCATION",
                    "ACCESS_BACKGROUND_LOCATION",
                    "READ_PHONE_STATE",
                ],
            }
        ],
    }
]


@pytest.fixture(autouse=True)
def no_cache(tmp_path):
    with patch("opsec_guard.utils.cache.CACHE_DIR", tmp_path):
        yield


def test_fetch_tiktok():
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.json.return_value = SAMPLE_EXODUS_RESPONSE
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        source = ExodusSource()
        profile = source.fetch("com.zhiliaoapp.musically", "android")

    assert profile is not None
    assert profile.collects_maid is True
    assert profile.links_maid_to_gps is True
    assert profile.background_location is True
    assert "ByteDance SDK" in profile.sdks
    assert profile.risk_score > 50


def test_fetch_ios_returns_none():
    source = ExodusSource()
    result = source.fetch("com.zhiliaoapp.musically", "ios")
    assert result is None


def test_fetch_http_error_returns_none():
    with patch("requests.get") as mock_get:
        mock_get.side_effect = Exception("Connection refused")
        source = ExodusSource()
        result = source.fetch("com.test.app", "android")
    assert result is None


def test_fetch_empty_response():
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        source = ExodusSource()
        result = source.fetch("com.notexist.app", "android")
    assert result is None


def test_cache_hit():
    with patch("opsec_guard.sources.exodus.cache_get") as mock_cache_get:
        mock_cache_get.return_value = SAMPLE_EXODUS_RESPONSE
        source = ExodusSource()
        profile = source.fetch("com.zhiliaoapp.musically", "android")
    assert profile is not None
    assert profile.collects_maid is True
