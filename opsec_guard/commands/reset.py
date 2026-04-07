import typer
from rich.panel import Panel
from rich.table import Table
from opsec_guard.utils.display import console


def _android_steps() -> None:
    console.print(Panel.fit("[bold green]Android — Reset GAID (Google Advertising ID)[/bold green]",
                            border_style="green"))
    console.print("""
[bold]Step 1 — Reset your GAID[/bold]
  Settings → Google → Ads → [bold cyan]Reset advertising ID[/bold cyan]
  (On some devices: Settings → Privacy → Ads)

  Each reset generates a brand-new random GAID, breaking prior linkage
  in broker databases. [dim]Recommended: reset weekly or monthly.[/dim]

[bold]Step 2 — Opt out of ads personalization[/bold]
  Settings → Google → Ads → [bold cyan]Delete advertising ID[/bold cyan]  (Android 12+)
  [dim]Or toggle: "Opt out of Ads Personalization"[/dim]

  On Android 12+, you can delete the GAID entirely. Apps will receive
  a string of zeros instead of a real identifier.

[bold]Step 3 — Audit location permissions[/bold]
  Settings → Apps → [each app] → Permissions → Location
  Change any [bold red]"Allow all the time"[/bold red] to [bold green]"Allow only while using"[/bold green] or [bold green]"Deny"[/bold green]
  unless the app has a legitimate real-time need.

[bold]Step 4 — Disable background location globally[/bold]
  Settings → Location → App permissions → filter by [bold]"Allowed all the time"[/bold]
  Review and revoke for any non-essential app.

[bold]Step 5 — Disable Wi-Fi scanning (fingerprinting vector)[/bold]
  Settings → Location → [bold cyan]Wi-Fi scanning[/bold cyan] → OFF
  Settings → Location → [bold cyan]Bluetooth scanning[/bold cyan] → OFF
  These allow location inference even when GPS/location is off.

[bold]Step 6 — Review installed apps[/bold]
  Run [bold cyan]opsec-guard maid scan[/bold cyan] on a connected device to identify
  apps with known MAID-harvesting SDKs.
""")


def _ios_steps() -> None:
    console.print(Panel.fit("[bold blue]iOS — Reset IDFA (Identifier for Advertisers)[/bold blue]",
                            border_style="blue"))
    console.print("""
[bold]Step 1 — Enable App Tracking Transparency (ATT)[/bold]
  Settings → Privacy & Security → Tracking
  Toggle [bold cyan]"Allow Apps to Request to Track"[/bold cyan] → [bold red]OFF[/bold red]

  This prevents apps from accessing your IDFA entirely. Any app that
  requests tracking will be automatically denied.

[bold]Step 2 — Reset your IDFA[/bold]
  Settings → Privacy & Security → Apple Advertising
  Tap [bold cyan]Reset Advertising Identifier[/bold cyan]

  [dim]Note: If ATT is fully disabled (Step 1), this step is less critical
  since apps cannot read your IDFA anyway.[/dim]

[bold]Step 3 — Disable Personalized Ads[/bold]
  Settings → Privacy & Security → Apple Advertising
  Toggle [bold cyan]Personalized Ads[/bold cyan] → [bold red]OFF[/bold red]

[bold]Step 4 — Audit location permissions[/bold]
  Settings → Privacy & Security → Location Services
  Review each app:
  • Change [bold red]"Always"[/bold red] to [bold green]"While Using"[/bold green] or [bold green]"Never"[/bold green]
  • Disable [bold cyan]Precise Location[/bold cyan] for apps that don't need exact GPS

[bold]Step 5 — Disable Significant Locations[/bold]
  Settings → Privacy & Security → Location Services → System Services
  Toggle [bold cyan]Significant Locations[/bold cyan] → [bold red]OFF[/bold red]
  This stops iOS from building a history of places you frequently visit.

[bold]Step 6 — Limit Share My Location[/bold]
  Settings → [your name] → Find My → Share My Location → [bold red]OFF[/bold red]
  [dim]Only re-enable if actively needed.[/dim]
""")


def _comparison_table() -> None:
    console.print(Panel.fit("[bold]Platform Comparison[/bold]", border_style="dim"))
    table = Table(show_header=True, header_style="bold white", box=None, padding=(0, 2))
    table.add_column("Feature", style="bold")
    table.add_column("Android", style="green")
    table.add_column("iOS", style="blue")

    rows = [
        ("MAID name",              "GAID (Google Advertising ID)",  "IDFA (Identifier for Advertisers)"),
        ("Reset location",         "Settings → Google → Ads",       "Settings → Privacy → Apple Advertising"),
        ("Delete MAID entirely",   "Android 12+ only",              "Via ATT opt-out (all versions)"),
        ("System-wide opt-out",    "Opt out of Ads Personalization", "Disable Allow Apps to Request to Track"),
        ("Fingerprinting risk",    "Higher (Wi-Fi/BT scanning)",    "Lower (Sandboxing + ATT enforcement)"),
        ("Background location",    "Manually revoke per app",       "Disable Precise Location per app"),
        ("Significant locations",  "Google Maps Timeline (disable)", "Settings → System Services → Sig. Locations"),
    ]
    for row in rows:
        table.add_row(*row)
    console.print(table)
    console.print()


def run_reset(platform: str | None) -> None:
    console.print()
    if platform is None:
        console.print("[dim]No platform specified — showing both. Use [bold]--platform android[/bold] or [bold]--platform ios[/bold][/dim]")
        console.print()
        _android_steps()
        _ios_steps()
    elif platform.lower() in ("android", "a"):
        _android_steps()
    elif platform.lower() in ("ios", "i", "iphone", "ipad"):
        _ios_steps()
    else:
        console.print(f"[red]Unknown platform '{platform}'. Use 'android' or 'ios'.[/red]")
        raise typer.Exit(1)

    _comparison_table()
    console.print("[dim]Tip: Reset your MAID regularly and run [bold]opsec-guard maid audit[/bold] to track your exposure score.[/dim]")
    console.print()
