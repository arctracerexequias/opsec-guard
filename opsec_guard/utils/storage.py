import json
import os
from datetime import datetime
from pathlib import Path

STORAGE_DIR = Path.home() / ".opsec-guard"
AUDITS_DIR  = STORAGE_DIR / "audits"


def ensure_dirs() -> None:
    AUDITS_DIR.mkdir(parents=True, exist_ok=True)


def save_audit(data: dict) -> Path:
    ensure_dirs()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = AUDITS_DIR / f"audit_{ts}.json"
    path.write_text(json.dumps(data, indent=2))
    return path


def load_latest_audit() -> dict | None:
    ensure_dirs()
    files = sorted(AUDITS_DIR.glob("audit_*.json"), reverse=True)
    if not files:
        return None
    return json.loads(files[0].read_text())


def list_audits() -> list[Path]:
    ensure_dirs()
    return sorted(AUDITS_DIR.glob("audit_*.json"), reverse=True)
