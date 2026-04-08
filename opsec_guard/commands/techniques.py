"""
opsec-guard maid techniques
Explains the full technical ecosystem behind MAID-based surveillance:
RTB, geofencing, BLE, fingerprinting, custom audiences, zero-click malware,
and pattern-of-life analysis.
"""
import json
from pathlib import Path
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from opsec_guard.utils.display import console, risk_badge

DATA_DIR = Path(__file__).parent.parent / "data"


def _load() -> list[dict]:
    return json.loads((DATA_DIR / "techniques.json").read_text())["techniques"]


def run_techniques(name: str | None) -> None:
    techniques = _load()
    console.print()

    if name:
        matches = [t for t in techniques if name.lower() in t["name"].lower()
                   or name.lower() in t["category"].lower()]
        if not matches:
            console.print(f"[yellow]No technique found matching '{name}'.[/yellow]")
            console.print("[dim]Available: " +
                          ", ".join(t["name"] for t in techniques) + "[/dim]")
            return
        for t in matches:
            _print_technique(t, detailed=True)
        return

    # Overview table
    console.print(Panel.fit(
        "[bold cyan]MAID Surveillance Techniques[/bold cyan]\n"
        "[dim]The full technical ecosystem — from ad auction to pattern-of-life profile[/dim]",
        border_style="cyan"
    ))
    console.print()

    table = Table(show_header=True, header_style="bold white", box=None, padding=(0, 2))
    table.add_column("#",          style="dim",  width=3)
    table.add_column("Technique",  style="bold", width=32)
    table.add_column("Category",   style="dim",  width=22)
    table.add_column("Precision",  width=20)
    table.add_column("Risk")

    for i, t in enumerate(techniques, 1):
        table.add_row(
            str(i),
            t["name"],
            t["category"],
            t["precision"],
            risk_badge(t["risk"]),
        )

    console.print(table)
    console.print()
    console.print("[dim]Run [bold]opsec-guard maid techniques <name>[/bold] "
                  "for full detail on any technique.[/dim]")
    console.print("[dim]Example: [bold]opsec-guard maid techniques RTB[/bold][/dim]")
    console.print()


def _print_technique(t: dict, detailed: bool = False) -> None:
    border = {"critical": "red", "high": "orange1",
              "medium": "yellow", "low": "green"}.get(t["risk"], "white")

    console.print(Panel.fit(
        f"[bold]{t['name']}[/bold]  {risk_badge(t['risk'])}\n"
        f"[dim]Category: {t['category']}  |  Precision: {t['precision']}[/dim]",
        border_style=border,
    ))

    console.print(f"\n  {t['summary']}\n")

    console.print(Rule("[bold]How It Works[/bold]"))
    console.print()
    for step in t["how_it_works"]:
        console.print(f"  {step}")
    console.print()

    console.print(Rule("[bold]Real-World Impact[/bold]"))
    console.print(f"\n  [bold red]•[/bold red] {t['real_world_impact']}\n")

    console.print(Rule("[bold]Mitigation[/bold]"))
    console.print(f"\n  [green]•[/green] {t['mitigation']}\n")
