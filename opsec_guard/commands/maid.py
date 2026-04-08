"""MAID commands — info, reset guide, and technique explainer."""
from __future__ import annotations
import json
from pathlib import Path

import typer
from rich.panel import Panel
from rich.table import Table

from ..utils.display import console

app = typer.Typer(help="MAID information, reset instructions, and attack technique guide.")

TECHNIQUES_FILE = Path(__file__).parent.parent / "data" / "techniques.json"


@app.command("info")
def info():
    """Explain what a MAID is and why it matters for personal security."""
    console.print(
        Panel(
            "[bold]What is a MAID?[/bold]\n\n"
            "A Mobile Advertising ID (MAID) is a unique identifier assigned to every smartphone:\n"
            "  • [info]Android:[/info] GAID (Google Advertising ID) — in Settings → Google → Ads\n"
            "  • [info]iOS:[/info] IDFA (Identifier for Advertisers) — in Settings → Privacy → Tracking\n\n"
            "[bold]Why is this a security concern?[/bold]\n\n"
            "Your MAID is the key that links your physical location to your digital identity.\n"
            "Every time an app loads an advertisement, your MAID plus GPS coordinates are\n"
            "transmitted to 200-500 advertising buyers in under 100 milliseconds.\n\n"
            "This creates a permanent, commercially available record of:\n"
            "  • Where you sleep (home address)\n"
            "  • Where you work (office location)\n"
            "  • Where you meet (boardrooms, hotels, government offices)\n"
            "  • Who you spend time with (co-location with other MAIDs)\n"
            "  • Your travel schedule (airports, transit patterns)\n\n"
            "[bold]Documented real-world exploitation:[/bold]\n\n"
            "  • 2021: French newspaper Le Monde traced 16 million MAIDs across France,\n"
            "    identifying individual politicians and officials by movement patterns.\n"
            "  • 2020: US DoD bought MAID datasets from Babel Street (Locate X) to track\n"
            "    individuals without a warrant — no court order required.\n"
            "  • 2019: A New York Times investigation identified US military personnel\n"
            "    at classified facilities using only commercial MAID location data.\n"
            "  • 2023: Predator spyware (Intellexa) delivered via mobile ad networks —\n"
            "    zero user interaction required.\n\n"
            "[dim]Philippines context: RTB-derived MAID data was used in the 2016 election\n"
            "micro-targeting campaign. Commercial datasets covering Metro Manila are\n"
            "available via Oracle Data Cloud and regional telco data resellers.[/dim]",
            title="[title]MAID — Mobile Advertising ID[/title]",
            border_style="cyan",
        )
    )


@app.command("reset")
def reset_guide():
    """Step-by-step MAID reset instructions for Android and iOS."""
    console.print(
        Panel(
            "[bold]Android — Reset GAID[/bold]\n\n"
            "  Method 1: Settings app\n"
            "    1. Open Settings → Google → Ads\n"
            "    2. Tap 'Reset advertising ID'\n"
            "    3. Confirm reset\n\n"
            "  Method 2: Android 12+ (Delete entirely)\n"
            "    1. Settings → Privacy → Ads\n"
            "    2. Tap 'Delete advertising ID'\n"
            "    3. This prevents apps from reading any MAID at all\n\n"
            "  ⚠️  [warn]Warning:[/warn] MAID reset alone is insufficient if apps use device\n"
            "  fingerprinting. Fingerprinting re-identifies your device using screen\n"
            "  resolution, GPU model, battery behavior, and other hardware signals.\n"
            "  For full re-identification prevention, factory reset is required.\n\n"
            "[bold]iOS — Disable IDFA[/bold]\n\n"
            "  Method 1: Per-app (iOS 14+)\n"
            "    1. Settings → Privacy & Security → Tracking\n"
            "    2. Toggle off 'Allow Apps to Request to Track'\n"
            "    3. Revoke tracking for individual apps shown\n\n"
            "  Method 2: Reset IDFA\n"
            "    1. Settings → Privacy & Security → Apple Advertising\n"
            "    2. Disable 'Personalized Ads'\n\n"
            "[bold]Recommended reset schedule:[/bold]\n\n"
            "  • Standard personnel:   Monthly (first day of each month)\n"
            "  • Executive tier:       Weekly (every Monday)\n"
            "  • High-risk travel:     Before and after every sensitive trip\n"
            "  • After flagged-zone:   Immediately after leaving flagged location\n\n"
            "[dim]After resetting, run: opsec-guard audit run  to re-assess your risk score.[/dim]",
            title="[title]MAID Reset Instructions[/title]",
            border_style="green",
        )
    )


@app.command("techniques")
def techniques(
    technique_id: str = typer.Argument(None, help="Technique ID (rtb|geofencing|bluetooth_beacon|device_fingerprinting|custom_audience|zero_click_malware|pattern_of_life)"),
):
    """Explain MAID exploitation techniques used against high-value individuals."""
    data = json.loads(TECHNIQUES_FILE.read_text())

    if technique_id:
        matches = [t for t in data if t["id"] == technique_id]
        if not matches:
            console.print(f"[warn]Technique '{technique_id}' not found.[/warn]")
            console.print(f"[dim]Available: {', '.join(t['id'] for t in data)}[/dim]")
            return
        data = matches

    for t in data:
        console.print(
            Panel(
                f"[bold]{t['name']}[/bold]\n\n"
                f"[info]Precision:[/info]    {t['precision']}\n"
                f"[info]Latency:[/info]      {t['latency']}\n"
                f"[info]Cost/exposure:[/info] {t['cost_per_exposure']}\n"
                f"[info]Activation:[/info]   {t['passive_or_active']}\n\n"
                f"[exec]Executive Threat:[/exec]\n{t['executive_threat']}\n\n"
                f"[warn]Real-World Cases:[/warn]\n"
                + "\n".join(f"  {c}" for c in t.get("real_world_cases", []))
                + f"\n\n[ok]Countermeasures:[/ok]\n"
                + "\n".join(f"  • {c}" for c in t.get("countermeasures", [])),
                title=f"[title]{t['name']}[/title]",
                border_style="yellow",
            )
        )
