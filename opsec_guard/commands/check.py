"""Check apps and brokers from local database with live source lookup."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table

from ..utils.display import console, risk_color, score_color
from ..sources.manager import fetch_merged_profile

app = typer.Typer(help="Check app and broker risk profiles.")

APPS_FILE = Path(__file__).parent.parent / "data" / "apps.json"
SDKS_FILE = Path(__file__).parent.parent / "data" / "sdks.json"
BROKERS_FILE = Path(__file__).parent.parent / "data" / "brokers.json"


def _load_apps() -> list[dict]:
    data = json.loads(APPS_FILE.read_text())
    if isinstance(data, dict):
        return data.get("apps", [])
    return data


def _load_brokers() -> list[dict]:
    data = json.loads(BROKERS_FILE.read_text())
    if isinstance(data, dict):
        return data.get("brokers", [])
    return data


def _load_sdks() -> list[dict]:
    data = json.loads(SDKS_FILE.read_text())
    if isinstance(data, dict):
        return data.get("sdks", [])
    return data


@app.command("app")
def check_app(
    query: str = typer.Argument(..., help="App name or package ID to look up"),
    live: bool = typer.Option(False, "--live", "-l", help="Query live external sources"),
    appcensus_key: Optional[str] = typer.Option(None, "--appcensus-key", help="AppCensus API key"),
):
    """Check an app's MAID risk profile."""
    apps = _load_apps()
    query_lower = query.lower()

    matches = [
        a for a in apps
        if query_lower in a.get("name", "").lower()
        or query_lower in a.get("package_android", "").lower()
        or query_lower in a.get("bundle_ios", "").lower()
        or query_lower in a.get("package", "").lower()
    ]

    if not matches and live:
        console.print(f"[dim]Not in local DB. Querying live sources for: {query}[/dim]")
        profile = fetch_merged_profile(query, appcensus_key=appcensus_key)
        if profile:
            _print_live_profile(profile)
        else:
            console.print(f"[warn]No data found for: {query}[/warn]")
        return

    if not matches:
        console.print(
            f"[warn]'{query}' not in local database.[/warn]\n"
            f"[dim]Try: opsec-guard check app {query} --live[/dim]"
        )
        return

    for app_data in matches:
        _print_app(app_data)


def _get_risk_score(a: dict) -> int:
    """Get risk score from either new (risk_score) or old (risk) field."""
    if "risk_score" in a:
        return int(a["risk_score"])
    risk_map = {"critical": 90, "high": 70, "medium": 50, "low": 20}
    return risk_map.get(str(a.get("risk", "")).lower(), 0)


def _print_app(a: dict) -> None:
    score = _get_risk_score(a)
    color = score_color(score)

    table = Table(title=f"{a.get('name', '?')} — Risk Score: {score}/100", show_header=False, show_lines=False)
    table.add_column("Field", style="dim", width=28)
    table.add_column("Value")

    def yn(v): return "[critical]YES[/critical]" if v else "[ok]No[/ok]"

    table.add_row("Risk Score", f"[{color}]{score}/100[/{color}]")
    pkg = a.get("package_android") or a.get("package", "—")
    bundle = a.get("bundle_ios", "—")
    table.add_row("Package (Android)", pkg)
    if bundle and bundle != "—":
        table.add_row("Bundle (iOS)", bundle)
    table.add_row("Collects MAID", yn(a.get("collects_maid")))
    table.add_row("Links MAID to GPS", yn(a.get("links_maid_to_gps")))
    if a.get("gps_precision_meters"):
        table.add_row("GPS Precision", f"{a['gps_precision_meters']}m")
    table.add_row("Background Location", yn(a.get("background_location")))
    table.add_row("RTB Participant", yn(a.get("rtb_participant")))
    table.add_row("Fingerprinting Fallback", yn(a.get("maid_fallback_fingerprinting")))
    sdks = a.get("sdks", [])
    if sdks:
        table.add_row("SDKs", ", ".join(sdks))
    brokers = a.get("brokers", [])
    if brokers:
        table.add_row("Brokers", ", ".join(brokers))

    console.print(table)

    exec_risk = a.get("executive_risk") or a.get("summary", "")
    if exec_risk:
        exec_color = "critical" if score >= 80 else "high" if score >= 60 else "medium"
        console.print(
            Panel(exec_risk, title="[exec]Executive Risk Context[/exec]", border_style=exec_color)
        )


def _print_live_profile(profile) -> None:
    color = score_color(profile.risk_score or 0)
    table = Table(
        title=f"{profile.app_name} (live) — Risk Score: {profile.risk_score or '?'}/100",
        show_header=False, show_lines=False,
    )
    table.add_column("Field", style="dim", width=28)
    table.add_column("Value")

    def yn(v): return "[critical]YES[/critical]" if v else "[ok]No[/ok]" if v is not None else "[dim]Unknown[/dim]"

    table.add_row("Source", profile.source)
    table.add_row("Platform", profile.platform)
    table.add_row("Collects MAID", yn(profile.collects_maid))
    table.add_row("Links MAID to GPS", yn(profile.links_maid_to_gps))
    table.add_row("Background Location", yn(profile.background_location))
    table.add_row("RTB Participant", yn(profile.rtb_participant))
    table.add_row("Fingerprinting", yn(profile.maid_fallback_fingerprinting))
    if profile.sdks:
        table.add_row("SDKs", ", ".join(profile.sdks[:6]))
    console.print(table)


@app.command("broker")
def check_broker(
    query: str = typer.Argument(..., help="Broker name to look up"),
):
    """Check a data broker's profile and opt-out instructions."""
    brokers = _load_brokers()
    query_lower = query.lower()
    matches = [b for b in brokers if query_lower in b.get("name", "").lower()]

    if not matches:
        console.print(f"[warn]Broker '{query}' not found in database.[/warn]")
        return

    for b in matches:
        rl = b.get("risk_level") or b.get("risk", "Medium")
        rl_str = rl.capitalize() if isinstance(rl, str) else "Medium"
        color = risk_color(rl_str)
        table = Table(title=b["name"], show_header=False, show_lines=False)
        table.add_column("Field", style="dim", width=25)
        table.add_column("Value")

        table.add_row("Risk Level", f"[{color}]{rl_str}[/{color}]")
        table.add_row("Country", b.get("country", "—"))
        data_types = b.get("data_types", b.get("data_types", []))
        if data_types:
            table.add_row("Data Types", ", ".join(data_types))
        clients = b.get("clients") or b.get("known_clients", [])
        if clients:
            table.add_row("Clients", ", ".join(clients))
        table.add_row("Govt Contractor", "[warn]YES[/warn]" if b.get("government_contractor") else "No")
        table.add_row("RTB Participant", "[warn]YES[/warn]" if b.get("rtb_participant") else "No")
        opt_out = b.get("opt_out_url") or b.get("opt_out_method", "No opt-out available")
        if opt_out:
            table.add_row("Opt-Out", str(opt_out))
        notes = b.get("notes") or b.get("incident", "")
        if notes:
            table.add_row("Notes", notes[:120])
        console.print(table)
