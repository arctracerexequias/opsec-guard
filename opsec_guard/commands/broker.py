"""Broker opt-out management — track and submit opt-outs for enrolled personnel."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table
from rich.panel import Panel

from ..utils.display import console, risk_color, tier_badge
from ..utils.storage import load_personnel, get_personnel, DATA_DIR

app = typer.Typer(help="Data broker opt-out management.")

BROKERS_FILE = Path(__file__).parent.parent / "data" / "brokers.json"
OPTOUTS_FILE = DATA_DIR / "broker_optouts.json"


def _load_brokers() -> list[dict]:
    return json.loads(BROKERS_FILE.read_text())


def _load_optouts() -> dict:
    if not OPTOUTS_FILE.exists():
        return {}
    return json.loads(OPTOUTS_FILE.read_text())


def _save_optouts(data: dict) -> None:
    DATA_DIR.mkdir(mode=0o700, exist_ok=True)
    OPTOUTS_FILE.write_text(json.dumps(data, indent=2))


@app.command("list")
def list_brokers(
    risk_filter: Optional[str] = typer.Option(None, "--risk", "-r", help="Filter by risk level"),
    opted_out_filter: Optional[bool] = typer.Option(None, "--opted-out", help="Show only opted out"),
):
    """List all tracked data brokers and opt-out status."""
    brokers = _load_brokers()
    optouts = _load_optouts()

    if risk_filter:
        brokers = [b for b in brokers if b.get("risk_level", "").lower() == risk_filter.lower()]

    table = Table(title="Data Broker Registry", show_lines=True)
    table.add_column("Broker", min_width=30)
    table.add_column("Risk", width=10)
    table.add_column("Country", width=8)
    table.add_column("Govt", width=6)
    table.add_column("RTB", width=5)
    table.add_column("Opt-Out Available", width=18)
    table.add_column("Status", width=12)

    for b in brokers:
        name = b["name"]
        rl = b.get("risk_level", "Medium")
        color = risk_color(rl)
        opted = optouts.get(name, {}).get("status", "")
        has_optout = bool(b.get("opt_out_url"))

        if opted_out_filter is True and opted != "done":
            continue
        if opted_out_filter is False and opted == "done":
            continue

        status = "[ok]Done[/ok]" if opted == "done" else "[warn]Pending[/warn]" if opted == "pending" else "[dim]—[/dim]"

        table.add_row(
            name,
            f"[{color}]{rl}[/{color}]",
            b.get("country", "?"),
            "[warn]Yes[/warn]" if b.get("government_contractor") else "No",
            "[warn]Yes[/warn]" if b.get("rtb_participant") else "No",
            "[ok]Yes[/ok]" if has_optout else "[critical]No[/critical]",
            status,
        )

    console.print(table)
    console.print(
        f"\n[dim]Brokers without opt-out (Critical): Fog Data Science, Babel Street, X-Mode — "
        f"no public removal available. Use MAID rotation + new device.[/dim]"
    )


@app.command("optout")
def optout(
    broker_name: str = typer.Argument(..., help="Broker name (partial match)"),
    person_id: Optional[str] = typer.Option(None, "--id", help="Personnel ID"),
    mark_done: bool = typer.Option(False, "--done", help="Mark as opted out"),
):
    """Show opt-out instructions for a broker."""
    brokers = _load_brokers()
    matches = [b for b in brokers if broker_name.lower() in b["name"].lower()]

    if not matches:
        console.print(f"[warn]Broker '{broker_name}' not found.[/warn]")
        return

    optouts = _load_optouts()
    b = matches[0]
    name = b["name"]

    opt_url = b.get("opt_out_url")
    opt_method = b.get("opt_out_method", "No method available")

    console.print(
        Panel(
            f"[bold]{name}[/bold]\n"
            f"Risk: [{risk_color(b.get('risk_level','Medium'))}]{b.get('risk_level','?')}[/{risk_color(b.get('risk_level','Medium'))}]\n"
            f"Govt Contractor: {'[warn]YES[/warn]' if b.get('government_contractor') else 'No'}\n\n"
            f"[info]Opt-Out Method:[/info] {opt_method}\n"
            + (f"[info]Opt-Out URL:[/info] {opt_url}\n" if opt_url else "[critical]No public opt-out available.[/critical]\n")
            + f"\n[dim]{b.get('notes', '')}[/dim]",
            title=f"Opt-Out: {name}",
            border_style="cyan",
        )
    )

    if mark_done:
        if name not in optouts:
            optouts[name] = {}
        optouts[name]["status"] = "done"
        optouts[name]["done_at"] = datetime.now(timezone.utc).isoformat()
        if person_id:
            optouts[name].setdefault("persons", []).append(person_id)
        _save_optouts(optouts)
        console.print(f"[ok]Marked {name} opt-out as complete.[/ok]")


@app.command("campaign")
def run_campaign(
    person_id: str = typer.Argument(..., help="Personnel ID"),
    dry_run: bool = typer.Option(True, "--dry-run/--run", help="Show plan without executing"),
):
    """Run a full broker opt-out campaign for a personnel member."""
    person = get_personnel(person_id)
    if not person:
        console.print(f"[warn]Personnel {person_id} not found.[/warn]")
        return

    brokers = _load_brokers()
    with_optout = [b for b in brokers if b.get("opt_out_url")]
    no_optout = [b for b in brokers if not b.get("opt_out_url")]

    console.print(
        Panel(
            f"[title]Broker Opt-Out Campaign[/title]\n"
            f"Personnel: {person.get('name')}  {tier_badge(person.get('tier','standard'))}\n\n"
            f"[ok]{len(with_optout)} brokers with opt-out available[/ok]\n"
            f"[critical]{len(no_optout)} brokers with NO opt-out (Fog, Babel Street, X-Mode)[/critical]\n\n"
            f"[dim]For brokers with no opt-out, the only mitigation is MAID rotation "
            f"and/or new device.[/dim]",
            border_style="cyan",
        )
    )

    if not dry_run:
        console.print(
            "\n[warn]Opening opt-out URLs. Complete each form manually.[/warn]\n"
            "[dim]This protects against commercial targeting. Govt-contractor brokers "
            "have no opt-out — rotate MAID monthly.[/dim]\n"
        )
        for b in with_optout:
            console.print(f"  → {b['name']}: {b['opt_out_url']}")
    else:
        console.print("\n[dim]Dry run — use --run to proceed with opt-out links.[/dim]")
