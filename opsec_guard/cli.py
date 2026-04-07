import typer
from opsec_guard.utils.display import console, banner

app = typer.Typer(
    name="opsec-guard",
    help="MAID exposure auditing and mobile geolocation privacy tool.",
    add_completion=False,
    no_args_is_help=True,
)

maid_app = typer.Typer(
    help="MAID (Mobile Advertising ID) exposure commands.",
    no_args_is_help=True,
)
app.add_typer(maid_app, name="maid")

# Import alert sub-app
from opsec_guard.commands.alerts import app as alerts_app
maid_app.add_typer(alerts_app, name="alerts")


@maid_app.command("info")
def info() -> None:
    """Explain what MAIDs are, how they are exploited, and real-world incidents."""
    from opsec_guard.commands.info import run_info
    banner()
    run_info()


@maid_app.command("reset")
def reset(
    platform: str = typer.Option(None, "--platform", "-p",
                                  help="Platform: android or ios. Shows both if omitted.")
) -> None:
    """Step-by-step guide to reset / delete your MAID on Android or iOS."""
    from opsec_guard.commands.reset import run_reset
    banner()
    run_reset(platform=platform)


@maid_app.command("audit")
def audit(
    save: bool = typer.Option(False, "--save", "-s",
                               help="Save audit results for report generation.")
) -> None:
    """Run an interactive MAID exposure audit and get a risk score."""
    from opsec_guard.commands.audit import run_audit
    banner()
    run_audit(save=save)


@maid_app.command("check")
def check(
    name: str = typer.Argument(..., help="App or SDK name to look up."),
    detailed: bool = typer.Option(False, "--detailed", "-d",
                                   help="Show source citations.")
) -> None:
    """Check if an app or SDK is known to harvest MAIDs and sell location data."""
    from opsec_guard.commands.check import run_check
    banner()
    run_check(app_name=name, detailed=detailed)


@maid_app.command("report")
def report(
    output: str = typer.Option("opsec_report.md", "--output", "-o",
                                help="Output file path."),
    fmt:    str = typer.Option("markdown",         "--format", "-f",
                                help="Output format: markdown or text.")
) -> None:
    """Generate a full MAID exposure report from the most recent saved audit."""
    from opsec_guard.commands.report import run_report
    banner()
    run_report(output=output, fmt=fmt)


@maid_app.command("scan")
def scan(
    device_id: str = typer.Option(None, "--device", "-d",
                                   help="ADB device serial (optional, uses first if omitted).")
) -> None:
    """Scan a connected Android device via ADB for known MAID-harvesting apps."""
    from opsec_guard.commands.scan import run_scan
    banner()
    run_scan(device_id=device_id)


@maid_app.command("fetch")
def fetch(
    query: str = typer.Argument(..., help="App name or package ID to look up."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass local cache and force fresh fetch."),
    sources_only: bool = typer.Option(False, "--sources", "-s", help="Show source availability status."),
    set_appcensus_key: str = typer.Option(None, "--set-appcensus-key",
                                           help="Save an AppCensus API key for dynamic analysis."),
    clear_cache: bool = typer.Option(False, "--clear-cache", help="Clear all cached fetch results."),
) -> None:
    """Fetch live MAID risk data from Exodus, Google Play, App Store, and AppCensus."""
    from opsec_guard.commands.fetch import run_fetch, run_set_appcensus_key, run_clear_cache
    banner()
    if set_appcensus_key:
        run_set_appcensus_key(set_appcensus_key)
        return
    if clear_cache:
        run_clear_cache()
        return
    run_fetch(query=query, no_cache=no_cache, sources_only=sources_only)


if __name__ == "__main__":
    app()
