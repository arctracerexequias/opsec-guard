"""OpsecGuard CLI — MAID Exposure Monitoring & Protection."""
import typer
from rich.panel import Panel

from .utils.display import console
from .commands import enroll, monitor, audit, check, broker, maid, alerts, org, report
from .server.run import app_cli as server_app

app = typer.Typer(
    name="opsec-guard",
    help=(
        "OpsecGuard — MAID Exposure Monitoring & Protection System\n\n"
        "Defends enrolled personnel from Mobile Advertising ID surveillance.\n"
        "Compliant with PH DPA RA 10173, GDPR, CCPA, ISO 27001, NIST SP 800-124."
    ),
    no_args_is_help=True,
)

app.add_typer(enroll.app, name="enroll", help="Enroll and manage protected personnel")
app.add_typer(monitor.app, name="monitor", help="Real-time device monitoring dashboard")
app.add_typer(audit.app, name="audit", help="Run MAID risk audits")
app.add_typer(check.app, name="check", help="Check app and broker risk profiles")
app.add_typer(broker.app, name="broker", help="Data broker opt-out management")
app.add_typer(maid.app, name="maid", help="MAID info, reset guide, attack techniques")
app.add_typer(alerts.app, name="alerts", help="Configure email alert system")
app.add_typer(org.app, name="org", help="OPSEC policies and compliance")
app.add_typer(report.app, name="report", help="Generate risk reports")
app.add_typer(server_app, name="server", help="Run the monitoring server")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        console.print(
            Panel(
                "[bold]OpsecGuard v2.0[/bold] — MAID Exposure Protection\n\n"
                "[info]Quick Start:[/info]\n\n"
                "  1. Enroll personnel:\n"
                "     [bold]opsec-guard enroll add[/bold]\n\n"
                "  2. Run a risk audit:\n"
                "     [bold]opsec-guard audit run[/bold]\n\n"
                "  3. Start the monitoring server:\n"
                "     [bold]opsec-guard server start --cert cert.pem --key key.pem[/bold]\n\n"
                "  4. Watch live dashboard:\n"
                "     [bold]opsec-guard monitor watch[/bold]\n\n"
                "  5. Check broker exposure:\n"
                "     [bold]opsec-guard broker list[/bold]\n\n"
                "  6. Check a specific app:\n"
                "     [bold]opsec-guard check app TikTok[/bold]\n\n"
                "[dim]Use --help with any command for details.[/dim]",
                title="OpsecGuard",
                border_style="cyan",
            )
        )
