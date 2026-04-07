import typer
from rich.panel import Panel
from rich.table import Table
from opsec_guard.utils.display import console
from opsec_guard.utils.alerts import load_config, save_config, send_critical_alert, CONFIG_PATH

app = typer.Typer(help="Configure and test critical alert emails.")


@app.command("configure")
def configure(
    recipient: str = typer.Option(None, "--to",        "-t", help="Recipient email address"),
    smtp_host: str = typer.Option(None, "--smtp-host", "-H", help="SMTP server hostname"),
    smtp_port: int = typer.Option(587,  "--smtp-port", "-P", help="SMTP port (default: 587)"),
    smtp_user: str = typer.Option(None, "--user",      "-u", help="SMTP username / sender email"),
) -> None:
    """Set up SMTP credentials for critical alert emails."""
    console.print()
    console.print(Panel.fit(
        "[bold cyan]Alert Email Configuration[/bold cyan]\n"
        "[dim]Credentials are stored locally at ~/.opsec-guard/alert_config.json[/dim]",
        border_style="cyan"
    ))

    existing = load_config() or {}

    if not recipient:
        recipient = typer.prompt("Recipient email", default=existing.get("recipient_email", ""))
    if not smtp_host:
        smtp_host = typer.prompt("SMTP host (e.g. smtp.gmail.com)", default=existing.get("smtp_host", ""))
    smtp_port_val = smtp_port if smtp_port != 587 else int(
        typer.prompt("SMTP port", default=str(existing.get("smtp_port", 587)))
    )
    if not smtp_user:
        smtp_user = typer.prompt("SMTP username / sender email", default=existing.get("smtp_user", ""))

    smtp_pass = typer.prompt("SMTP password (app password recommended)", hide_input=True)

    cfg = {
        "recipient_email": recipient,
        "smtp_host":       smtp_host,
        "smtp_port":       smtp_port_val,
        "smtp_user":       smtp_user,
        "smtp_password":   smtp_pass,
        "sender_email":    smtp_user,
    }
    save_config(cfg)

    console.print()
    console.print(f"[green]Configuration saved to {CONFIG_PATH}[/green]")
    console.print("[dim]Run [bold]opsec-guard maid alerts test[/bold] to send a test alert.[/dim]")
    console.print()


@app.command("test")
def test() -> None:
    """Send a test critical alert using the saved configuration."""
    console.print()
    cfg = load_config()
    if cfg is None:
        console.print(Panel(
            "[yellow]No configuration found.[/yellow]\n\n"
            "Run [bold cyan]opsec-guard maid alerts configure[/bold cyan] first.",
            border_style="yellow"
        ))
        raise typer.Exit(1)

    console.print(f"[dim]Sending test alert to [bold]{cfg['recipient_email']}[/bold]...[/dim]")

    ok, msg = send_critical_alert(
        findings=[
            "TEST: MAID has never been reset — persistent tracking profile likely exists.",
            "TEST: Weather app with background location access detected.",
            "TEST: 5+ apps have Always-On location permission.",
        ],
        score=85,
        level="critical",
    )

    if ok:
        console.print(f"[green]{msg}[/green]")
    else:
        console.print(f"[red]Failed: {msg}[/red]")
    console.print()


@app.command("show")
def show() -> None:
    """Show current alert configuration (password hidden)."""
    console.print()
    cfg = load_config()
    if cfg is None:
        console.print("[yellow]No configuration found. Run `opsec-guard maid alerts configure`.[/yellow]")
        return

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold cyan", width=20)
    table.add_column("Value")
    table.add_row("Recipient",  cfg.get("recipient_email", ""))
    table.add_row("SMTP Host",  cfg.get("smtp_host", ""))
    table.add_row("SMTP Port",  str(cfg.get("smtp_port", 587)))
    table.add_row("SMTP User",  cfg.get("smtp_user", ""))
    table.add_row("Password",   "[dim]*** (hidden)[/dim]")
    console.print(table)
    console.print()


@app.command("clear")
def clear() -> None:
    """Remove saved alert configuration."""
    if CONFIG_PATH.exists():
        CONFIG_PATH.unlink()
        console.print("[green]Alert configuration removed.[/green]")
    else:
        console.print("[dim]No configuration to remove.[/dim]")
    console.print()
