"""Live monitoring dashboard — shows real-time device status for all enrolled personnel."""
from __future__ import annotations
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

import typer
from rich.table import Table
from rich.live import Live
from rich.panel import Panel

from ..utils.display import console, tier_badge, risk_color
from ..utils.storage import load_personnel, latest_report_per_device, load_device_reports
from ..utils.geo import check_flagged_locations
from ..utils.alerts import send_executive_alert
from ..server.run import ensure_server_running, get_server_url, DEFAULT_PORT

app = typer.Typer(help="Real-time device monitoring dashboard.")

OFFLINE_THRESHOLD_MINUTES = 10
ALERT_COOLDOWN_SECONDS = 300  # Don't re-alert same issue within 5 minutes

_sent_alerts: dict[str, float] = {}


def _last_seen_label(report: dict) -> str:
    received = report.get("received_at", "")
    if not received:
        return "[warn]Never[/warn]"
    try:
        dt = datetime.fromisoformat(received)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - dt
        if delta < timedelta(minutes=1):
            return "[ok]Just now[/ok]"
        if delta < timedelta(minutes=5):
            return f"[ok]{int(delta.total_seconds() // 60)}m ago[/ok]"
        if delta < timedelta(minutes=OFFLINE_THRESHOLD_MINUTES):
            return f"[warn]{int(delta.total_seconds() // 60)}m ago[/warn]"
        return f"[critical]OFFLINE {int(delta.total_seconds() // 60)}m[/critical]"
    except Exception:
        return "[dim]Unknown[/dim]"


def _is_offline(report: dict) -> bool:
    received = report.get("received_at", "")
    if not received:
        return True
    try:
        dt = datetime.fromisoformat(received)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - dt > timedelta(minutes=OFFLINE_THRESHOLD_MINUTES)
    except Exception:
        return True


def _risk_flags(report: dict) -> list[str]:
    flags = []
    if report.get("risky_apps"):
        flags.append(f"[high]{len(report['risky_apps'])} risky apps[/high]")
    if report.get("flagged_locations"):
        for loc in report["flagged_locations"]:
            flags.append(f"[critical]FLAGGED ZONE: {loc['name'][:30]}[/critical]")
    if report.get("maid_not_reset"):
        flags.append("[warn]MAID not reset >30d[/warn]")
    if report.get("new_risky_app"):
        flags.append(f"[high]NEW risky app: {report['new_risky_app']}[/high]")
    return flags


def _build_table(personnel: list[dict], device_reports: dict[str, dict]) -> Table:
    table = Table(title="OpsecGuard — Live Monitor", show_lines=True, expand=True)
    table.add_column("ID", style="cyan", width=10)
    table.add_column("Name", width=20)
    table.add_column("Tier", width=16)
    table.add_column("Platform", width=10)
    table.add_column("MAID", width=36)
    table.add_column("Last Seen", width=15)
    table.add_column("Status / Alerts", min_width=30)

    for person in personnel:
        pid = person["id"]
        report = device_reports.get(pid, {})
        last_seen = _last_seen_label(report)
        flags = _risk_flags(report)
        maid = report.get("maid", "[dim]—[/dim]")
        offline = _is_offline(report) and report

        if offline:
            status = "[critical]OFFLINE[/critical]"
        elif flags:
            status = " · ".join(flags)
        else:
            status = "[ok]Clean[/ok]"

        table.add_row(
            pid,
            person.get("name", ""),
            tier_badge(person.get("tier", "standard")),
            person.get("platform", ""),
            f"[dim]{maid[:34]}[/dim]" if maid != "[dim]—[/dim]" else maid,
            last_seen,
            status,
        )

    return table


def _check_and_send_alerts(personnel: list[dict], device_reports: dict[str, dict]) -> None:
    now = time.time()
    for person in personnel:
        pid = person["id"]
        report = device_reports.get(pid, {})
        if not report:
            continue

        def _alert(key: str, subject: str, body: str) -> None:
            alert_key = f"{pid}:{key}"
            if now - _sent_alerts.get(alert_key, 0) < ALERT_COOLDOWN_SECONDS:
                return
            _sent_alerts[alert_key] = now
            send_executive_alert(person, subject, body)

        # Flagged location alert
        for loc in report.get("flagged_locations", []):
            _alert(
                f"flagged:{loc['name']}",
                f"Flagged Zone Alert — {loc['risk_level']} Risk",
                f"Personnel {person['name']} is near a flagged location:\n\n"
                f"Location: {loc['name']}\n"
                f"Risk Level: {loc['risk_level']}\n"
                f"Distance: {loc.get('distance_meters', '?')}m\n"
                f"Reason: {loc['reason']}\n\n"
                f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            )

        # Offline alert (executive only)
        if person.get("tier") == "executive" and _is_offline(report):
            _alert(
                "offline",
                "Executive Device Offline",
                f"Executive device for {person['name']} has not reported in "
                f">{OFFLINE_THRESHOLD_MINUTES} minutes.\n\n"
                f"Last seen: {report.get('received_at', 'Unknown')}\n"
                f"Device ID: {report.get('device_id', pid)}",
            )

        # New risky app
        if report.get("new_risky_app"):
            _alert(
                f"new_app:{report['new_risky_app']}",
                f"New High-Risk App Detected",
                f"A high-risk app was installed on {person['name']}'s device:\n\n"
                f"App: {report['new_risky_app']}\n"
                f"Risk: MAID collection and/or GPS tracking detected\n\n"
                f"Recommendation: Review and uninstall if not required for work.",
            )


@app.command("watch")
def watch(
    refresh: int = typer.Option(10, "--refresh", "-r", help="Refresh interval in seconds"),
    alerts: bool = typer.Option(True, "--alerts/--no-alerts", help="Send email alerts"),
    person_id: Optional[str] = typer.Option(None, "--id", help="Filter to specific personnel ID"),
    port: int = typer.Option(DEFAULT_PORT, "--port", "-p", help="Server port"),
    ssl_cert: Optional[str] = typer.Option(None, "--cert", help="TLS cert for auto-started server"),
    ssl_key: Optional[str] = typer.Option(None, "--key", help="TLS key for auto-started server"),
):
    """Live monitoring dashboard — auto-starts the monitoring server if not running."""
    # Auto-start server
    already_running, server_url = ensure_server_running(
        port=port, ssl_cert=ssl_cert, ssl_key=ssl_key
    )
    if already_running:
        console.print(f"[ok]Server already running:[/ok] [dim]{server_url}[/dim]")
    else:
        console.print(f"[ok]Server started:[/ok] [dim]{server_url}[/dim]")
    console.print(f"[dim]Agent reports to: {server_url}/report[/dim]")
    console.print("[dim]Press Ctrl+C to stop monitor (server keeps running in background)[/dim]\n")

    with Live(console=console, refresh_per_second=1) as live:
        while True:
            try:
                personnel = load_personnel()
                if person_id:
                    personnel = [p for p in personnel if p["id"] == person_id]

                device_reports = latest_report_per_device()
                # Map reports by person ID (device reports use person_id field)
                pid_reports = {r.get("person_id", ""): r for r in device_reports.values()}

                table = _build_table(personnel, pid_reports)
                timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                live.update(
                    Panel(
                        table,
                        subtitle=f"[dim]Last updated: {timestamp} · Refresh: {refresh}s[/dim]",
                        border_style="cyan",
                    )
                )

                if alerts:
                    _check_and_send_alerts(personnel, pid_reports)

                time.sleep(refresh)
            except KeyboardInterrupt:
                break

    console.print("[dim]Monitor stopped.[/dim]")


@app.command("status")
def status(
    person_id: Optional[str] = typer.Argument(None, help="Personnel ID (omit for all)"),
):
    """Show current device status snapshot."""
    from ..server.run import is_port_open, DEFAULT_PORT
    server_up = is_port_open(port=DEFAULT_PORT)
    url = get_server_url()
    console.print(
        f"[{'ok' if server_up else 'warn'}]Server: {'UP' if server_up else 'DOWN'} — {url}[/{'ok' if server_up else 'warn'}]"
    )

    personnel = load_personnel()
    if not personnel:
        console.print("[dim]No personnel enrolled. Use: opsec-guard enroll add[/dim]")
        return

    if person_id:
        personnel = [p for p in personnel if p["id"] == person_id]
        if not personnel:
            console.print(f"[warn]Personnel {person_id} not found.[/warn]")
            return

    device_reports = latest_report_per_device()
    pid_reports = {r.get("person_id", ""): r for r in device_reports.values()}
    console.print(_build_table(personnel, pid_reports))


@app.command("server-stop")
def server_stop():
    """Stop the background monitoring server."""
    import signal
    from ..server.run import DEFAULT_PORT, _load_server_config
    cfg = _load_server_config()
    port = cfg.get("port", DEFAULT_PORT)

    # Find and kill the uvicorn process bound to our port
    try:
        import subprocess
        result = subprocess.run(
            ["fuser", f"{port}/tcp"],
            capture_output=True, text=True,
        )
        pids = result.stdout.strip().split()
        if not pids:
            console.print(f"[dim]No server process found on port {port}.[/dim]")
            return
        for pid in pids:
            try:
                import os
                os.kill(int(pid), signal.SIGTERM)
            except (ProcessLookupError, ValueError):
                pass
        console.print(f"[ok]Server stopped (port {port}).[/ok]")
    except FileNotFoundError:
        console.print("[warn]fuser not available. Kill the server process manually.[/warn]")
