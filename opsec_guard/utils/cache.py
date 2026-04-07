import json
import hashlib
import time
from pathlib import Path

CACHE_DIR = Path.home() / ".opsec-guard" / "cache"
DEFAULT_TTL = 86400  # 24 hours


def _key(source: str, identifier: str) -> Path:
    slug = hashlib.sha256(f"{source}:{identifier}".encode()).hexdigest()[:16]
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{source}_{slug}.json"


def get(source: str, identifier: str, ttl: int = DEFAULT_TTL) -> dict | None:
    path = _key(source, identifier)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        if time.time() - data.get("_cached_at", 0) > ttl:
            path.unlink(missing_ok=True)
            return None
        return data.get("payload")
    except (json.JSONDecodeError, OSError):
        return None


def set(source: str, identifier: str, payload: dict) -> None:
    path = _key(source, identifier)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"_cached_at": time.time(), "payload": payload}))


def invalidate(source: str, identifier: str) -> None:
    _key(source, identifier).unlink(missing_ok=True)


def clear_all() -> int:
    count = 0
    if CACHE_DIR.exists():
        for f in CACHE_DIR.glob("*.json"):
            f.unlink()
            count += 1
    return count
