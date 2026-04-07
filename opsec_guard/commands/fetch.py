import typer
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.spinner import Spinner
from rich.live import Live
from rich.text import Text
from opsec_guard.utils.display import console, risk_badge
from opsec_guard.sources.manager import fetch_all, source_status
from opsec_guard.sources.appcensus import save_api_key, load_api_key
from opsec_guard.utils.cache import clear_all


def run_fetch(query: str, no_cache: bool, sources_only: bool) -> None:
    if sources_only:
        _show_sources()
        return

    console.print()
    console.print(f"[dim]Querying external sources for:[/dim] [bold]{query}[/bold]")
    console.print()

    profile = None
    with Live(
        Text("  Fetching from Exodus, Google Play, App Store, AppCensus...", style="dim"),
        console=console,
        refresh_per_second=4,
        transient=True,
    ):
        from opsec_guard.utils.cache import clear_all as _clear
        if no_cache:
            from opsec_guard.utils import cache as _cache
            for src in ("exodus", "google_play", "app_store", "appcensus"):
                _cache.invalidate(src, query)
        profile = fetch_all(query)

    _print_profile(profile)


def _print_profile(profile) -> None:
    hits = profile.sources_hit or []
    checked = profile.sources_checked or []
    missed = [s for s in checked if s not in hits]

    console.print(Panel.fit(
        f"[bold]{profile.name}[/bold]"
        + (f"  [dim]({profile.package})[/dim]" if profile.package else "")
        + f"  {risk_badge(profile.risk_level)}\n"
        f"[dim]Platform: {profile.platform}  |  "
        f"Sources hit: {', '.join(hits) if hits else 'none'}[/dim]",
        border_style={
            "critical": "red", "high": "orange1",
            "medium": "yellow", "low": "green",
        }.get(profile.risk_level, "white"),
    ))

    # MAID risk summary
    maid_label = (
        "[bold red]YES — MAID transmission confirmed or declared[/bold red]" if profile.maid_risk is True
        else "[bold green]Not detected[/bold green]" if profile.maid_risk is False
        else "[dim]Inconclusive (no data)[/dim]"
    )
    console.print(f"  MAID Risk : {maid_label}")
    console.print()

    # Core data table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold cyan", width=26)
    table.add_column("Value")

    if profile.maid_trackers:
        table.add_row(
            "MAID-reading trackers",
            "[red]" + ", ".join(profile.maid_trackers) + "[/red]"
        )
    if profile.trackers:
        others = [t for t in profile.trackers if t not in profile.maid_trackers]
        if others:
            table.add_row("Other trackers", ", ".join(others[:8]) +
                          (f" (+{len(others)-8} more)" if len(others) > 8 else ""))

    if profile.permissions:
        table.add_row("Sensitive permissions", "\n".join(profile.permissions[:6]))

    if profile.data_collected:
        table.add_row("Data collected (declared)", ", ".join(profile.data_collected[:6]))

    if profile.data_shared:
        table.add_row("Data shared with 3rd parties", ", ".join(profile.data_shared[:6]))

    if table.row_count > 0:
        console.print(table)
        console.print()

    # Findings
    if profile.findings:
        console.print(Rule("[bold]Findings[/bold]"))
        console.print()
        for f in profile.findings:
            console.print(f"  [bold red]•[/bold red] {f}")
        console.print()

    # Sources that returned nothing
    if missed:
        console.print(f"[dim]No data from: {', '.join(missed)}[/dim]")

    console.print("[dim]Run with [bold]--no-cache[/bold] to force a fresh fetch.[/dim]")
    console.print()


def _show_sources() -> None:
    console.print()
    console.print(Panel.fit("[bold cyan]External Source Status[/bold cyan]", border_style="cyan"))

    table = Table(show_header=True, header_style="bold white", box=None, padding=(0, 2))
    table.add_column("Source",    style="bold")
    table.add_column("Platform",  style="dim")
    table.add_column("Status")
    table.add_column("Notes", style="dim")

    notes = {
        "exodus":      "Free public API — no key needed",
        "google_play": "Requires: pip install google-play-scraper",
        "app_store":   "Free iTunes Search API — no key needed",
        "appcensus":   "Requires API key — run: opsec-guard maid fetch --set-appcensus-key",
    }

    for s in source_status():
        status = "[green]Available[/green]" if s["available"] else "[red]Unavailable[/red]"
        table.add_row(s["name"], s["platform"], status, notes.get(s["name"], ""))

    console.print(table)

    appcensus_key = load_api_key()
    if not appcensus_key:
        console.print()
        console.print("[dim]AppCensus key not set. Get a free key at https://appcensus.io "
                      "then run:[/dim]")
        console.print("[bold]  opsec-guard maid fetch --set-appcensus-key <key>[/bold]")
    console.print()


def run_set_appcensus_key(key: str) -> None:
    save_api_key(key)
    console.print(f"[green]AppCensus API key saved.[/green]")


def run_clear_cache() -> None:
    count = clear_all()
    console.print(f"[green]Cleared {count} cached entries.[/green]")
