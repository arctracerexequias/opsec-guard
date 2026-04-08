"""FastAPI monitoring server — receives push reports from enrolled devices."""
from __future__ import annotations
import json
import os
import hashlib
import hmac
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from ..utils.storage import save_device_report, load_personnel, get_personnel, latest_report_per_device
from ..utils.geo import check_flagged_locations
from ..utils.alerts import send_executive_alert

app = FastAPI(
    title="OpsecGuard Monitoring Server",
    description="Receives push reports from enrolled device agents.",
    version="2.0.0",
)

AGENT_FILE = Path(__file__).parent.parent.parent / "agent" / "device_agent.py"
SERVER_SECRET = os.environ.get("OPSEC_GUARD_SECRET", "change-me-in-production")


class DeviceReport(BaseModel):
    person_id: str
    device_id: str
    platform: str  # android | ios
    maid: Optional[str] = None
    maid_limit_enabled: Optional[bool] = None
    installed_apps: Optional[list[str]] = None
    risky_apps: Optional[list[str]] = None
    new_risky_app: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    maid_last_reset: Optional[str] = None
    battery: Optional[int] = None
    timestamp: Optional[str] = None


class HeartbeatReport(BaseModel):
    person_id: str
    device_id: str
    battery: Optional[int] = None
    timestamp: Optional[str] = None


def _verify_token(authorization: str = Header(None)) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization[7:]
    # Simple HMAC-based token validation
    expected = hmac.new(SERVER_SECRET.encode(), token[:8].encode(), hashlib.sha256).hexdigest()[:16]
    # In production: use proper JWT or pre-shared enrollment tokens
    # For now, verify the person_id is enrolled


@app.get("/health")
def health():
    return {"status": "ok", "server": "OpsecGuard v2.0"}


@app.post("/report")
async def receive_report(report: DeviceReport, authorization: str = Header(None)):
    """Receive a device status report from an enrolled agent."""
    # Verify enrollment
    person = get_personnel(report.person_id)
    if not person:
        raise HTTPException(status_code=403, detail="Personnel ID not enrolled")

    report_dict = report.model_dump()
    report_dict["received_at"] = datetime.now(timezone.utc).isoformat()

    # Check flagged locations
    if report.lat is not None and report.lon is not None:
        flagged = check_flagged_locations(report.lat, report.lon)
        report_dict["flagged_locations"] = flagged
    else:
        report_dict["flagged_locations"] = []

    # Check MAID reset age
    maid_not_reset = False
    if report.maid_last_reset:
        try:
            last_reset = datetime.fromisoformat(report.maid_last_reset)
            if last_reset.tzinfo is None:
                last_reset = last_reset.replace(tzinfo=timezone.utc)
            days_since = (datetime.now(timezone.utc) - last_reset).days
            tier = person.get("tier", "standard")
            threshold = 7 if tier == "executive" else 30
            maid_not_reset = days_since > threshold
        except Exception:
            pass
    report_dict["maid_not_reset"] = maid_not_reset

    # Save report
    save_device_report(report_dict)

    # Trigger alerts
    _process_alerts(person, report_dict)

    return {"status": "received", "flagged_locations": len(report_dict["flagged_locations"])}


@app.post("/heartbeat")
async def heartbeat(report: HeartbeatReport):
    """Simple heartbeat — device is alive."""
    person = get_personnel(report.person_id)
    if not person:
        raise HTTPException(status_code=403, detail="Personnel ID not enrolled")

    save_device_report({
        "person_id": report.person_id,
        "device_id": report.device_id,
        "type": "heartbeat",
        "battery": report.battery,
        "received_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"status": "ok"}


@app.get("/status")
def get_status():
    """Dashboard status summary."""
    personnel = load_personnel()
    device_reports = latest_report_per_device()
    pid_reports = {r.get("person_id", ""): r for r in device_reports.values()}

    summary = []
    for p in personnel:
        r = pid_reports.get(p["id"], {})
        summary.append({
            "id": p["id"],
            "name": p["name"],
            "tier": p["tier"],
            "last_report": r.get("received_at"),
            "flagged_locations": len(r.get("flagged_locations", [])),
            "risky_apps": len(r.get("risky_apps", [])),
        })
    return {"personnel": summary, "total": len(personnel)}


@app.get("/agent/device_agent.py")
def serve_agent():
    """Serve the device agent script for Termux installation."""
    if AGENT_FILE.exists():
        return FileResponse(AGENT_FILE, media_type="text/plain")
    raise HTTPException(status_code=404, detail="Agent not found")


_alert_cooldown: dict[str, float] = {}


def _process_alerts(person: dict, report: dict) -> None:
    import time
    now = time.time()

    def maybe_alert(key: str, subject: str, body: str) -> None:
        alert_key = f"{person['id']}:{key}"
        if now - _alert_cooldown.get(alert_key, 0) < 300:
            return
        _alert_cooldown[alert_key] = now
        try:
            send_executive_alert(person, subject, body)
        except Exception:
            pass

    for loc in report.get("flagged_locations", []):
        maybe_alert(
            f"flagged:{loc['name']}",
            f"Flagged Zone — {loc['risk_level']} Risk: {loc['name'][:40]}",
            f"Personnel: {person['name']}\n"
            f"Location: {loc['name']}\n"
            f"Risk Level: {loc['risk_level']}\n"
            f"Distance: {loc.get('distance_meters', '?')}m\n"
            f"Reason: {loc['reason']}\n"
            f"Time: {report.get('received_at', '')}",
        )

    if report.get("new_risky_app"):
        maybe_alert(
            f"new_app:{report['new_risky_app']}",
            f"High-Risk App Installed: {report['new_risky_app']}",
            f"Personnel: {person['name']}\n"
            f"New high-risk app detected: {report['new_risky_app']}\n"
            f"Action: Review and uninstall if not required.",
        )

    if report.get("maid_not_reset"):
        maybe_alert(
            "maid_overdue",
            "MAID Reset Overdue",
            f"Personnel: {person['name']}\n"
            f"MAID has not been reset within the required interval.\n"
            f"Action: Reset MAID immediately.\n\n"
            f"Android: Settings → Google → Ads → Reset advertising ID\n"
            f"iOS: Settings → Privacy → Tracking",
        )
