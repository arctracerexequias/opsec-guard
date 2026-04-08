"""Tests for TTL cache."""
import pytest
from unittest.mock import patch
from pathlib import Path


@pytest.fixture(autouse=True)
def temp_cache(tmp_path):
    with patch("opsec_guard.utils.cache.CACHE_DIR", tmp_path):
        yield tmp_path


def test_set_and_get():
    from opsec_guard.utils.cache import get, set
    set("test_key", {"foo": "bar"})
    result = get("test_key")
    assert result == {"foo": "bar"}


def test_get_nonexistent():
    from opsec_guard.utils.cache import get
    assert get("nonexistent_key") is None


def test_cache_list():
    from opsec_guard.utils.cache import get, set
    set("list_key", [1, 2, 3])
    assert get("list_key") == [1, 2, 3]


def test_invalidate():
    from opsec_guard.utils.cache import get, set, invalidate
    set("to_remove", {"data": True})
    invalidate("to_remove")
    assert get("to_remove") is None


def test_clear_all():
    from opsec_guard.utils.cache import set, clear_all, get
    set("key1", {"a": 1})
    set("key2", {"b": 2})
    count = clear_all()
    assert count == 2
    assert get("key1") is None


def test_ttl_expiry():
    from opsec_guard.utils.cache import get, set
    from datetime import datetime, timezone, timedelta
    import json

    set("ttl_key", {"fresh": True})

    # Manually backdate the cache file
    import hashlib, os
    from opsec_guard.utils.cache import CACHE_DIR
    key = hashlib.md5("ttl_key".encode()).hexdigest()
    cache_file = CACHE_DIR / f"{key}.json"
    data = json.loads(cache_file.read_text())
    data["_cached_at"] = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    cache_file.write_text(json.dumps(data))

    assert get("ttl_key") is None
