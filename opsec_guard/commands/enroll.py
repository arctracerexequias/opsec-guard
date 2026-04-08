"""Personnel enrollment with consent-first framework and executive tier support."""
from __future__ import annotations
import uuid
import json
import qrcode
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm

from ..utils.display import console, tier_badge
from ..utils.storage import enroll_personnel, load_personnel, get_personnel, remove_personnel

app = typer.Typer(help="Enroll, list, and manage protected personnel.")

CONSENT_TEXT = """
INFORMED CONSENT — OpsecGuard MAID Monitoring Program

By enrolling in this program, I understand and agree that:

1. PURPOSE: This monitoring program is designed to protect my mobile device
   from Mobile Advertising ID (MAID) exposure and associated surveillance risks.

2. DATA COLLECTED: Device MAID (GAID/IDFA), installed applications, approximate
   GPS location (when available via device agent), and app risk reports.

3. LEGAL BASIS: Collection is based on my explicit consent (GDPR Art. 6(1)(a);
   PH DPA RA 10173 Sec. 12(a)) and legitimate organizational security interest.

4. DATA RETENTION: Records retained for 12 months or until de-enrollment,
   whichever is sooner. Encrypted with AES-256 at rest.

5. MY RIGHTS: I may withdraw consent and request deletion at any time by
   running: opsec-guard enroll remove <my-id>

6. NO SURVEILLANCE: This system does NOT track location for disciplinary
   purposes. Location data is used solely for flagged-zone proximity alerts.

7. COMPLIANCE: Program operates under PH DPA RA 10173, GDPR, CCPA, ISO 27001,
   and NIST SP 800-124 Mobile Device Security Guidelines.
"""


@app.command("add")
def add_personnel(
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Full name"),
    email: Optional[str] = typer.Option(None, "--email", "-e", help="Email address"),
    tier: str = typer.Option("standard", "--tier", "-t", help="Tier: standard | executive"),
    officer_email: Optional[str] = typer.Option(
        None, "--officer-email", help="Security officer email (executive tier)"
    ),
    role: Optional[str] = typer.Option(None, "--role", "-r", help="Job title / role"),
    device_platform: str = typer.Option(
        "android", "--platform", "-p", help="Device platform: android | ios"
    ),
    no_confirm: bool = typer.Option(False, "--yes", "-y", help="Skip consent prompt"),
):
    """Enroll a new protected personnel member (consent required)."""
    console.rule("[title]OpsecGuard — Personnel Enrollment[/title]")

    if not name:
        name = Prompt.ask("[info]Full name[/info]")
    if not email:
        email = Prompt.ask("[info]Email address[/info]")
    if not role:
        role = Prompt.ask("[info]Role / Job title[/info]", default="")

    if tier == "executive":
        console.print(
            Panel(
                "[exec]Executive Tier[/exec] — Elevated protection level:\n"
                "• Alerts forwarded to designated security officer\n"
                "• High-priority email flagging\n"
                "• Executive risk profile applied (custom audience, boardroom geofencing)\n"
                "• Quarterly broker opt-out campaign included",
                title="★ Executive Tier",
                border_style="magenta",
            )
        )
        if not officer_email:
            officer_email = Prompt.ask(
                "[exec]Security officer email[/exec] (receives escalated alerts)",
                default="",
            )

    # Consent
    console.print(Panel(CONSENT_TEXT.strip(), title="Informed Consent", border_style="yellow"))
    if not no_confirm:
        if not Confirm.ask("\n[warn]Does the personnel member consent to enrollment?[/warn]"):
            console.print("[warn]Enrollment cancelled — consent not given.[/warn]")
            raise typer.Exit()

    person_id = str(uuid.uuid4())[:8].upper()
    record = {
        "id": person_id,
        "name": name,
        "email": email,
        "role": role,
        "tier": tier,
        "platform": device_platform,
        "security_officer_email": officer_email or None,
        "enrolled_at": datetime.now(timezone.utc).isoformat(),
        "consent_given": True,
        "consent_timestamp": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }

    enroll_personnel(record)

    console.print(
        Panel(
            f"[ok]Enrollment successful![/ok]\n\n"
            f"  Name:     {name}\n"
            f"  ID:       [bold]{person_id}[/bold]\n"
            f"  Tier:     {tier_badge(tier)}\n"
            f"  Platform: {device_platform}\n"
            f"  Email:    {email}\n"
            + (f"  Officer:  {officer_email}\n" if officer_email else "")
            + f"\n[dim]Share this ID with the personnel for device agent setup.[/dim]",
            title="Enrolled",
            border_style="green",
        )
    )

    # Generate QR for executive tier
    if tier == "executive":
        _print_qr_setup(person_id, device_platform)


@app.command("list")
def list_personnel():
    """List all enrolled personnel."""
    records = load_personnel()
    if not records:
        console.print("[dim]No personnel enrolled.[/dim]")
        return

    table = Table(title="Enrolled Personnel", show_lines=True)
    table.add_column("ID", style="bold cyan", width=10)
    table.add_column("Name", style="white")
    table.add_column("Role", style="dim")
    table.add_column("Tier", width=16)
    table.add_column("Platform", width=10)
    table.add_column("Email", style="dim")
    table.add_column("Enrolled", width=12)

    for r in records:
        enrolled = r.get("enrolled_at", "")[:10]
        table.add_row(
            r["id"],
            r.get("name", ""),
            r.get("role", ""),
            tier_badge(r.get("tier", "standard")),
            r.get("platform", ""),
            r.get("email", ""),
            enrolled,
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(records)} personnel enrolled[/dim]")


@app.command("remove")
def remove_person(
    person_id: str = typer.Argument(..., help="Personnel ID to remove"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """Remove a personnel member and delete their data (right to erasure)."""
    person = get_personnel(person_id)
    if not person:
        console.print(f"[warn]Personnel ID {person_id} not found.[/warn]")
        raise typer.Exit(1)

    console.print(
        f"[warn]Remove {person.get('name')} (ID: {person_id}) and delete all their data?[/warn]"
    )
    if not force and not Confirm.ask("Confirm removal"):
        console.print("[dim]Cancelled.[/dim]")
        return

    remove_personnel(person_id)
    console.print(f"[ok]Personnel {person_id} ({person.get('name')}) removed. Data deleted.[/ok]")
    console.print("[dim]This satisfies PH DPA Sec. 34 and GDPR Art. 17 (Right to Erasure).[/dim]")


@app.command("setup-agent")
def setup_agent(
    person_id: str = typer.Argument(..., help="Personnel ID"),
    server_url: str = typer.Option(..., "--server", "-s", help="Monitoring server HTTPS URL"),
):
    """Print device agent setup instructions for a personnel member."""
    person = get_personnel(person_id)
    if not person:
        console.print(f"[warn]Personnel ID {person_id} not found.[/warn]")
        raise typer.Exit(1)

    platform = person.get("platform", "android")
    name = person.get("name", "")
    tier = person.get("tier", "standard")

    console.print(
        Panel(
            f"[title]Device Agent Setup — {name}[/title]\n"
            f"Tier: {tier_badge(tier)}\n\n"
            + _agent_instructions(person_id, server_url, platform),
            title="Agent Setup",
            border_style="cyan",
        )
    )
    _print_qr_setup(person_id, platform, server_url)


def _agent_instructions(person_id: str, server_url: str, platform: str) -> str:
    if platform == "android":
        return (
            f"[bold]Android (Termux) — one-liner install:[/bold]\n\n"
            f"  1. Install Termux from F-Droid (NOT Play Store)\n"
            f"  2. Run:\n\n"
            f"     pkg install python\n"
            f"     pip install requests\n"
            f"     curl -L {server_url}/agent/device_agent.py -o ~/device_agent.py\n"
            f"     python ~/device_agent.py --id {person_id} --server {server_url}\n\n"
            f"  3. Keep Termux running (acquire wakelock in Termux settings)\n"
            f"  4. The agent runs silently and reports every 30 seconds on change.\n"
        )
    else:
        return (
            f"[bold]iOS — Shortcut-based agent:[/bold]\n\n"
            f"  1. Install the OpsecGuard shortcut from:\n"
            f"     {server_url}/agent/ios_shortcut\n\n"
            f"  2. Set Personal ID: {person_id}\n"
            f"  3. Set Server URL: {server_url}\n"
            f"  4. Enable automation to run every 15 minutes.\n\n"
            f"  Note: iOS IDFA requires Settings → Privacy → Tracking → per-app.\n"
        )


def _print_qr_setup(person_id: str, platform: str, server_url: str = "https://your-server") -> None:
    try:
        payload = json.dumps({"id": person_id, "platform": platform, "server": server_url})
        qr = qrcode.QRCode(border=1)
        qr.add_data(payload)
        qr.make(fit=True)
        f = io.StringIO()
        qr.print_ascii(out=f)
        console.print("\n[exec]Executive QR Setup Code[/exec] (scan to auto-configure agent):")
        console.print(f.getvalue())
    except ImportError:
        console.print(f"\n[dim]Install qrcode for QR display: pip install qrcode[/dim]")
        console.print(f"[dim]Setup payload: personnel_id={person_id}[/dim]")
