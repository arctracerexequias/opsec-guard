#!/usr/bin/env python3
"""
OpsecGuard Device Agent v2.0
Runs on enrolled Android devices via Termux.

Install:
  pkg install python
  pip install requests
  python device_agent.py --id <PERSONNEL_ID> --server https://<SERVER>

Keeps running silently. Reports to monitoring server on change.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    print("Installing requests...")
    subprocess.run([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests

VERSION = "2.0.0"
STATE_FILE = Path.home() / ".opsecguard_state.json"
CONFIG_FILE = Path.home() / ".opsecguard_config.json"

REPORT_INTERVAL = 30        # seconds between full scans
HEARTBEAT_INTERVAL = 300    # 5 min heartbeat
FULL_SCAN_INTERVAL = 1800   # 30 min full app scan

# High-risk packages — checked against installed apps
HIGH_RISK_PACKAGES = {
    "com.zhiliaoapp.musically",     # TikTok
    "com.facebook.katana",          # Facebook
    "com.instagram.android",        # Instagram
    "com.bitsmedia.android.muslimpro",  # Muslim Pro
    "com.weather.Weather",          # Weather Channel
    "com.king.candycrushsaga",      # Candy Crush
    "com.zhiliaoapp.musically.go",  # TikTok Lite
    "com.facebook.lite",            # Facebook Lite
}


def _get_gaid() -> str | None:
    """Read GAID from Android settings database via content provider."""
    try:
        result = subprocess.run(
            ["content", "query", "--uri",
             "content://com.google.android.gsf.gservices/prefix",
             "--where", "name=android_id"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and "value=" in result.stdout:
            for line in result.stdout.splitlines():
                if "value=" in line:
                    return line.split("value=")[-1].strip()
    except Exception:
        pass

    # Fallback: try via settings
    try:
        result = subprocess.run(
            ["settings", "get", "secure", "advertising_id"],
            capture_output=True, text=True, timeout=5,
        )
        val = result.stdout.strip()
        if val and val != "null":
            return val
    except Exception:
        pass

    # Last resort: generate stable device pseudonym (not real GAID but stable)
    try:
        device_id = subprocess.run(
            ["getprop", "ro.serialno"],
            capture_output=True, text=True, timeout=3,
        ).stdout.strip()
        if device_id:
            return "pseudo-" + hashlib.md5(device_id.encode()).hexdigest()
    except Exception:
        pass

    return None


def _get_installed_packages() -> list[str]:
    """List installed APK packages via pm list packages."""
    try:
        result = subprocess.run(
            ["pm", "list", "packages"],
            capture_output=True, text=True, timeout=15,
        )
        return [
            line.replace("package:", "").strip()
            for line in result.stdout.splitlines()
            if line.startswith("package:")
        ]
    except Exception:
        return []


def _get_location() -> tuple[float | None, float | None]:
    """Try to get location via Termux:API if installed."""
    try:
        result = subprocess.run(
            ["termux-location", "-p", "network", "-r", "once"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return data.get("latitude"), data.get("longitude")
    except Exception:
        pass
    return None, None


def _get_battery() -> int | None:
    """Get battery level via Termux:API."""
    try:
        result = subprocess.run(
            ["termux-battery-status"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return data.get("percentage")
    except Exception:
        pass
    return None


def _get_maid_last_reset() -> str | None:
    """Read stored MAID reset timestamp."""
    reset_file = Path.home() / ".opsecguard_maid_reset"
    if reset_file.exists():
        return reset_file.read_text().strip()
    return None


def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"maid": None, "installed_apps_hash": "", "last_heartbeat": 0, "last_full_scan": 0}


def _save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state))


def _post_report(server: str, person_id: str, device_id: str, data: dict, verify_ssl: bool = True) -> bool:
    try:
        resp = requests.post(
            f"{server}/report",
            json={
                "person_id": person_id,
                "device_id": device_id,
                "platform": "android",
                **data,
            },
            timeout=15,
            verify=verify_ssl,
        )
        return resp.status_code == 200
    except Exception as e:
        print(f"[{_ts()}] Report failed: {e}", flush=True)
        return False


def _post_heartbeat(server: str, person_id: str, device_id: str, battery: int | None, verify_ssl: bool = True) -> None:
    try:
        requests.post(
            f"{server}/heartbeat",
            json={
                "person_id": person_id,
                "device_id": device_id,
                "battery": battery,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            timeout=10,
            verify=verify_ssl,
        )
    except Exception:
        pass


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _device_id(person_id: str) -> str:
    """Stable anonymous device identifier."""
    try:
        serial = subprocess.run(
            ["getprop", "ro.serialno"], capture_output=True, text=True, timeout=3
        ).stdout.strip()
        if serial:
            return "dv-" + hashlib.sha256(f"{person_id}:{serial}".encode()).hexdigest()[:16]
    except Exception:
        pass
    return "dv-" + hashlib.sha256(person_id.encode()).hexdigest()[:16]


def run(person_id: str, server: str, no_ssl_verify: bool = False):
    verify_ssl = not no_ssl_verify
    dev_id = _device_id(person_id)
    print(f"OpsecGuard Agent v{VERSION}", flush=True)
    print(f"Personnel ID: {person_id}", flush=True)
    print(f"Device ID:    {dev_id}", flush=True)
    print(f"Server:       {server}", flush=True)
    print(f"Press Ctrl+C to stop.\n", flush=True)

    state = _load_state()
    last_heartbeat = state.get("last_heartbeat", 0)
    last_full_scan = state.get("last_full_scan", 0)
    known_risky: set[str] = set(state.get("known_risky", []))

    while True:
        now = time.time()
        report_data: dict = {"timestamp": datetime.now(timezone.utc).isoformat()}
        changed = False

        # ── MAID check ────────────────────────────────────────────────
        current_maid = _get_gaid()
        if current_maid != state.get("maid"):
            state["maid"] = current_maid
            changed = True
            print(f"[{_ts()}] MAID changed → {current_maid}", flush=True)
        report_data["maid"] = current_maid
        report_data["maid_last_reset"] = _get_maid_last_reset()

        # ── Full app scan (every 30 min) ───────────────────────────────
        if now - last_full_scan >= FULL_SCAN_INTERVAL:
            packages = _get_installed_packages()
            pkg_hash = hashlib.md5("|".join(sorted(packages)).encode()).hexdigest()

            risky = [p for p in packages if p in HIGH_RISK_PACKAGES]
            new_risky = [p for p in risky if p not in known_risky]

            if pkg_hash != state.get("installed_apps_hash", ""):
                state["installed_apps_hash"] = pkg_hash
                changed = True

            if new_risky:
                report_data["new_risky_app"] = new_risky[0]
                known_risky.update(new_risky)
                state["known_risky"] = list(known_risky)
                changed = True
                print(f"[{_ts()}] NEW risky app: {new_risky[0]}", flush=True)

            report_data["risky_apps"] = risky
            last_full_scan = now
            state["last_full_scan"] = now

        # ── Location (if Termux:API available) ────────────────────────
        lat, lon = _get_location()
        if lat is not None:
            report_data["lat"] = lat
            report_data["lon"] = lon

        # ── Battery ───────────────────────────────────────────────────
        report_data["battery"] = _get_battery()

        # ── Send report if changed ─────────────────────────────────────
        if changed:
            ok = _post_report(server, person_id, dev_id, report_data, verify_ssl)
            if ok:
                print(f"[{_ts()}] Report sent OK", flush=True)
            _save_state(state)

        # ── Heartbeat every 5 min ─────────────────────────────────────
        if now - last_heartbeat >= HEARTBEAT_INTERVAL:
            _post_heartbeat(server, person_id, dev_id, report_data.get("battery"), verify_ssl)
            last_heartbeat = now
            state["last_heartbeat"] = now
            _save_state(state)
            print(f"[{_ts()}] Heartbeat", flush=True)

        time.sleep(REPORT_INTERVAL)


def main():
    parser = argparse.ArgumentParser(description="OpsecGuard Device Agent")
    parser.add_argument("--id", required=True, help="Personnel ID from enrollment")
    parser.add_argument("--server", required=True, help="Monitoring server HTTPS URL")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL verification (dev only)")
    args = parser.parse_args()

    if args.no_ssl_verify:
        print("WARNING: SSL verification disabled. Only use in development.", flush=True)
        import urllib3
        urllib3.disable_warnings()

    try:
        run(args.id, args.server.rstrip("/"), args.no_ssl_verify)
    except KeyboardInterrupt:
        print("\nAgent stopped.", flush=True)


if __name__ == "__main__":
    main()
