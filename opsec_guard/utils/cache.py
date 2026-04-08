"""24-hour TTL JSON file cache for external API results."""
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta

CACHE_DIR = Path.home() / ".opsec-guard" / "cache"
TTL_HOURS = 24


def _cache_path(key: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe = hashlib.md5(key.encode()).hexdigest()
    return CACHE_DIR / f"{safe}.json"


def get(key: str) -> dict | list | None:
    path = _cache_path(key)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        cached_at = datetime.fromisoformat(data["_cached_at"])
        if datetime.now(timezone.utc) - cached_at > timedelta(hours=TTL_HOURS):
            path.unlink(missing_ok=True)
            return None
        return data["payload"]
    except Exception:
        return None


def set(key: str, payload: dict | list) -> None:
    path = _cache_path(key)
    data = {
        "_cached_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }
    path.write_text(json.dumps(data, indent=2))


def invalidate(key: str) -> None:
    _cache_path(key).unlink(missing_ok=True)


def clear_all() -> int:
    if not CACHE_DIR.exists():
        return 0
    count = 0
    for f in CACHE_DIR.glob("*.json"):
        f.unlink()
        count += 1
    return count
