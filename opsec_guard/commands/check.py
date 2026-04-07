import json
from pathlib import Path
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from opsec_guard.utils.display import console, risk_badge

DATA_DIR = Path(__file__).parent.parent / "data"


def _load_db() -> tuple[list, list, list]:
    apps    = json.loads((DATA_DIR / "apps.json").read_text())["apps"]
    sdks    = json.loads((DATA_DIR / "sdks.json").read_text())["sdks"]
    brokers = json.loads((DATA_DIR / "brokers.json").read_text())["brokers"]
    return apps, sdks, brokers


def _fuzzy_match(query: str, name: str) -> bool:
    q = query.lower().strip()
    n = name.lower()
    return q in n or n in q or any(word in n for word in q.split() if len(word) > 3)


def _print_app(app: dict, detailed: bool) -> None:
    console.print()
    console.print(Panel.fit(
        f"[bold]{app['name']}[/bold]  {risk_badge(app['risk'])}\n"
        f"[dim]Package: {app['package']}  |  Category: {app['category']}[/dim]",
        border_style=_border(app["risk"])
    ))

    console.print(f"  [bold]Summary:[/bold] {app['summary']}")
    console.print()

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold cyan", width=28)
    table.add_column("Value")

    yn = lambda b: "[red]YES[/red]" if b else "[green]NO[/green]"
    gps = f"{app['gps_precision_meters']}m" if app['gps_precision_meters'] else "N/A"

    table.add_row("Collects MAID",           yn(app["collects_maid"]))
    table.add_row("Links MAID to GPS",        yn(app["links_maid_to_gps"]))
    table.add_row("GPS precision",            gps)
    table.add_row("Background location",      yn(app["background_location"]))
    table.add_row("Fingerprinting fallback",  yn(app["maid_fallback_fingerprinting"]))

    if app["brokers"]:
        table.add_row("Known data brokers", ", ".join(app["brokers"]))
    else:
        table.add_row("Known data brokers", "[dim]None documented[/dim]")

    if detailed:
        table.add_row("Sources", "\n".join(app["sources"]))

    console.print(table)
    console.print()


def _print_sdk(sdk: dict, detailed: bool) -> None:
    console.print()
    console.print(Panel.fit(
        f"[bold]{sdk['name']}[/bold]  {risk_badge(sdk['risk'])}  [dim](SDK)[/dim]\n"
        f"[dim]Category: {sdk['category']}[/dim]",
        border_style=_border(sdk["risk"])
    ))

    console.print(f"  [bold]Summary:[/bold] {sdk['summary']}")
    console.print()

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold cyan", width=28)
    table.add_column("Value")

    yn = lambda b: "[red]YES[/red]" if b else "[green]NO[/green]"

    table.add_row("Reads MAID",                  yn(sdk["reads_maid"]))
    table.add_row("Transmits MAID+GPS",           yn(sdk["transmits_maid_gps"]))
    table.add_row("RTB participant",              yn(sdk["rtb_participant"]))
    table.add_row("Fingerprinting fallback",      yn(sdk["fingerprinting_fallback"]))
    table.add_row("Known clients / embedded in",  ", ".join(sdk["clients"]) if sdk["clients"] else "[dim]Unknown[/dim]")

    if detailed:
        table.add_row("Sources", "\n".join(sdk["sources"]))

    console.print(table)
    console.print()


def _print_broker(broker: dict, detailed: bool) -> None:
    console.print()
    console.print(Panel.fit(
        f"[bold]{broker['name']}[/bold]  {risk_badge(broker['risk'])}  [dim](Data Broker)[/dim]",
        border_style=_border(broker["risk"])
    ))

    console.print(f"  [bold]Incident:[/bold] {broker['incident']}")
    console.print()

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold cyan", width=28)
    table.add_column("Value")

    table.add_row("Data types",    ", ".join(broker["data_types"]))
    table.add_row("Known clients", ", ".join(broker["known_clients"]))

    if broker["opt_out_url"]:
        table.add_row("Opt-out URL", broker["opt_out_url"])
    else:
        table.add_row("Opt-out URL", "[red]None available[/red]")

    if detailed:
        table.add_row("Sources", "\n".join(broker["sources"]))

    console.print(table)
    console.print()


def _border(risk: str) -> str:
    return {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green"}.get(risk, "white")


def run_check(app_name: str, detailed: bool) -> None:
    apps, sdks, brokers = _load_db()

    app_hits    = [a for a in apps    if _fuzzy_match(app_name, a["name"]) or _fuzzy_match(app_name, a.get("package", ""))]
    sdk_hits    = [s for s in sdks    if _fuzzy_match(app_name, s["name"])]
    broker_hits = [b for b in brokers if _fuzzy_match(app_name, b["name"])]

    total = len(app_hits) + len(sdk_hits) + len(broker_hits)

    console.print()
    if total == 0:
        console.print(Panel.fit(
            f"[bold]'{app_name}'[/bold] — [green]Not found in MAID threat database[/green]\n\n"
            "[dim]This doesn't mean the app is safe — it may simply not be documented yet.\n"
            "Check the app's privacy policy for mentions of advertising identifiers,\n"
            "MAID, IDFA, GAID, or third-party SDKs like AppLovin, ironSource, or Braze.[/dim]",
            border_style="green"
        ))
        return

    console.print(Rule(f"[bold]Results for '{app_name}'[/bold] — {total} match(es) found"))

    for app in app_hits:
        _print_app(app, detailed)

    for sdk in sdk_hits:
        _print_sdk(sdk, detailed)

    for broker in broker_hits:
        _print_broker(broker, detailed)

    if not detailed:
        console.print("[dim]Run with [bold]--detailed[/bold] to see source citations.[/dim]")
    console.print()
