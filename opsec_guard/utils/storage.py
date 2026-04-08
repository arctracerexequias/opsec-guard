"""Encrypted local storage for enrolled personnel and audit results."""
import json
import os
import base64
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from cryptography.fernet import Fernet

DATA_DIR = Path.home() / ".opsec-guard"
PERSONNEL_FILE = DATA_DIR / "personnel.enc"
AUDIT_FILE = DATA_DIR / "audits.enc"
KEY_FILE = DATA_DIR / ".key"


def _ensure_dir() -> None:
    DATA_DIR.mkdir(mode=0o700, exist_ok=True)


def _get_or_create_key() -> bytes:
    _ensure_dir()
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    KEY_FILE.chmod(0o600)
    return key


def _fernet() -> Fernet:
    return Fernet(_get_or_create_key())


def _read_enc(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        raw = _fernet().decrypt(path.read_bytes())
        return json.loads(raw)
    except Exception:
        return []


def _write_enc(path: Path, data: list[dict]) -> None:
    _ensure_dir()
    encrypted = _fernet().encrypt(json.dumps(data).encode())
    path.write_bytes(encrypted)
    path.chmod(0o600)


# ── Personnel ──────────────────────────────────────────────────────────────


def load_personnel() -> list[dict]:
    return _read_enc(PERSONNEL_FILE)


def save_personnel(records: list[dict]) -> None:
    _write_enc(PERSONNEL_FILE, records)


def enroll_personnel(record: dict) -> None:
    records = load_personnel()
    existing = next(
        (i for i, r in enumerate(records) if r.get("id") == record.get("id")), None
    )
    if existing is not None:
        records[existing] = record
    else:
        records.append(record)
    save_personnel(records)


def get_personnel(person_id: str) -> dict | None:
    return next(
        (r for r in load_personnel() if r.get("id") == person_id), None
    )


def remove_personnel(person_id: str) -> bool:
    records = load_personnel()
    new_records = [r for r in records if r.get("id") != person_id]
    if len(new_records) == len(records):
        return False
    save_personnel(new_records)
    return True


# ── Audit Results ──────────────────────────────────────────────────────────


def load_audits() -> list[dict]:
    return _read_enc(AUDIT_FILE)


def save_audit(result: dict) -> None:
    audits = load_audits()
    audits.append({**result, "saved_at": datetime.now(timezone.utc).isoformat()})
    _write_enc(AUDIT_FILE, audits)


def get_audits_for_person(person_id: str) -> list[dict]:
    return [a for a in load_audits() if a.get("person_id") == person_id]


# ── Device Reports (push-based) ────────────────────────────────────────────

REPORTS_FILE = DATA_DIR / "device_reports.enc"


def save_device_report(report: dict) -> None:
    reports = _read_enc(REPORTS_FILE)
    reports.append({**report, "received_at": datetime.now(timezone.utc).isoformat()})
    _write_enc(REPORTS_FILE, reports[-10000:])


def load_device_reports(device_id: str | None = None) -> list[dict]:
    reports = _read_enc(REPORTS_FILE)
    if device_id:
        return [r for r in reports if r.get("device_id") == device_id]
    return reports


def latest_report_per_device() -> dict[str, dict]:
    """Returns the most recent report for each device_id."""
    reports = load_device_reports()
    latest: dict[str, dict] = {}
    for r in reports:
        did = r.get("device_id", "unknown")
        if did not in latest or r.get("received_at", "") > latest[did].get("received_at", ""):
            latest[did] = r
    return latest
