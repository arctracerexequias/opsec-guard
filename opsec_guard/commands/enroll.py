"""Personnel enrollment with consent-first framework and executive tier support."""
from __future__ import annotations
import uuid
import json
import csv
import io as _io
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
    server_url: Optional[str] = typer.Option(None, "--server", "-s", help="Monitoring server URL (auto-detected if omitted)"),
):
    """Print device agent setup instructions for a personnel member."""
    from ..server.run import get_server_url
    person = get_personnel(person_id)
    if not person:
        console.print(f"[warn]Personnel ID {person_id} not found.[/warn]")
        raise typer.Exit(1)

    if not server_url:
        server_url = get_server_url()
        console.print(f"[dim]Using server URL from config: {server_url}[/dim]")

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


CSV_TEMPLATE_ROWS = [
    ["name", "email", "role", "tier", "platform", "security_officer_email"],
    ["Juan dela Cruz", "juan@corp.com", "CEO", "executive", "android", "cso@corp.com"],
    ["Maria Santos", "maria@corp.com", "CFO", "executive", "ios", "cso@corp.com"],
    ["Pedro Reyes", "pedro@corp.com", "IT Staff", "standard", "android", ""],
    ["Ana Garcia", "ana@corp.com", "Legal Counsel", "standard", "ios", ""],
]

CSV_REQUIRED = {"name", "email"}
CSV_OPTIONAL = {
    "role": "",
    "tier": "standard",
    "platform": "android",
    "security_officer_email": None,
}


def _build_record(row: dict) -> dict:
    """Build a personnel record from a CSV row dict."""
    tier = row.get("tier", "standard").strip().lower()
    if tier not in ("standard", "executive"):
        tier = "standard"
    platform = row.get("platform", "android").strip().lower()
    if platform not in ("android", "ios"):
        platform = "android"
    officer = row.get("security_officer_email", "").strip() or None

    return {
        "id": str(uuid.uuid4())[:8].upper(),
        "name": row["name"].strip(),
        "email": row["email"].strip(),
        "role": row.get("role", "").strip(),
        "tier": tier,
        "platform": platform,
        "security_officer_email": officer,
        "enrolled_at": datetime.now(timezone.utc).isoformat(),
        "consent_given": True,
        "consent_timestamp": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }


@app.command("import")
def import_csv(
    csv_file: Path = typer.Argument(..., help="Path to CSV file"),
    skip_existing: bool = typer.Option(True, "--skip-existing/--update-existing",
                                        help="Skip rows whose email is already enrolled"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without saving"),
    no_confirm: bool = typer.Option(False, "--yes", "-y", help="Skip consent confirmation"),
):
    """Bulk enroll personnel from a CSV file."""
    if not csv_file.exists():
        console.print(f"[critical]File not found: {csv_file}[/critical]")
        raise typer.Exit(1)

    try:
        with open(csv_file, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    except Exception as e:
        console.print(f"[critical]Cannot read CSV: {e}[/critical]")
        raise typer.Exit(1)

    if not rows:
        console.print("[warn]CSV file is empty.[/warn]")
        return

    # Validate required columns
    headers = {h.strip().lower() for h in (rows[0].keys() if rows else [])}
    missing = CSV_REQUIRED - headers
    if missing:
        console.print(f"[critical]Missing required columns: {', '.join(missing)}[/critical]")
        console.print(f"[dim]Required: name, email  |  Optional: role, tier, platform, security_officer_email[/dim]")
        raise typer.Exit(1)

    # Normalise header names (strip whitespace, lowercase)
    rows = [{k.strip().lower(): v for k, v in row.items()} for row in rows]

    # Load existing to check for duplicates by email
    existing_personnel = load_personnel()
    existing_emails = {r.get("email", "").lower() for r in existing_personnel}

    # Preview table
    table = Table(title=f"CSV Import Preview — {len(rows)} rows", show_lines=True)
    table.add_column("#", width=4, style="dim")
    table.add_column("Name")
    table.add_column("Email")
    table.add_column("Role", style="dim")
    table.add_column("Tier", width=16)
    table.add_column("Platform", width=10)
    table.add_column("Status", width=14)

    valid_rows = []
    skipped = 0
    errors = 0

    for i, row in enumerate(rows, 1):
        name = row.get("name", "").strip()
        email = row.get("email", "").strip()

        if not name or not email:
            status = "[critical]Missing name/email[/critical]"
            errors += 1
        elif "@" not in email:
            status = "[critical]Invalid email[/critical]"
            errors += 1
        elif email.lower() in existing_emails and skip_existing:
            status = "[warn]Already enrolled[/warn]"
            skipped += 1
        else:
            status = "[ok]Ready[/ok]"
            valid_rows.append(row)

        tier = row.get("tier", "standard").strip().lower()
        table.add_row(
            str(i),
            name,
            email,
            row.get("role", ""),
            tier_badge(tier if tier in ("standard", "executive") else "standard"),
            row.get("platform", "android"),
            status,
        )

    console.print(table)
    console.print(
        f"\n[ok]{len(valid_rows)} to enroll[/ok]  "
        f"[warn]{skipped} already enrolled[/warn]  "
        f"[critical]{errors} errors[/critical]"
    )

    if not valid_rows:
        console.print("[dim]Nothing to enroll.[/dim]")
        return

    if dry_run:
        console.print("\n[dim]Dry run — no changes made. Remove --dry-run to enroll.[/dim]")
        return

    # Consent confirmation (one batch consent for CSV imports)
    console.print(
        Panel(
            "[bold]Batch Consent Declaration[/bold]\n\n"
            "By proceeding, you confirm that all personnel listed in this CSV\n"
            "have been individually informed of the monitoring program and have\n"
            "given their explicit consent as required by:\n"
            "  • PH DPA RA 10173 Sec. 12(a)\n"
            "  • GDPR Art. 6(1)(a)\n\n"
            "Consent records will be stored with each personnel entry.",
            border_style="yellow",
        )
    )

    if not no_confirm:
        if not Confirm.ask("[warn]Confirm that all listed personnel have consented?[/warn]"):
            console.print("[warn]Import cancelled.[/warn]")
            return

    # Enroll
    enrolled = []
    failed = []
    for row in valid_rows:
        try:
            record = _build_record(row)
            enroll_personnel(record)
            enrolled.append(record)
        except Exception as e:
            failed.append((row.get("name", "?"), str(e)))

    # Results table
    result_table = Table(title=f"Enrollment Results — {len(enrolled)} enrolled", show_lines=True)
    result_table.add_column("ID", style="bold cyan", width=10)
    result_table.add_column("Name")
    result_table.add_column("Email", style="dim")
    result_table.add_column("Tier", width=16)

    for r in enrolled:
        result_table.add_row(
            r["id"],
            r["name"],
            r["email"],
            tier_badge(r["tier"]),
        )

    console.print(result_table)

    if failed:
        for name, err in failed:
            console.print(f"[critical]Failed: {name} — {err}[/critical]")

    console.print(
        f"\n[ok]{len(enrolled)} personnel enrolled successfully.[/ok]"
        + (f"\n[dim]Export IDs with: opsec-guard enroll export[/dim]" if enrolled else "")
    )


@app.command("template")
def csv_template(
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save to file (default: print to screen)"),
):
    """Print or save a CSV template for bulk enrollment."""
    buf = _io.StringIO()
    writer = csv.writer(buf)
    for row in CSV_TEMPLATE_ROWS:
        writer.writerow(row)
    content = buf.getvalue()

    if output:
        output.write_text(content)
        console.print(f"[ok]Template saved: {output}[/ok]")
        console.print(f"[dim]Edit and import with: opsec-guard enroll import {output}[/dim]")
    else:
        console.print("[bold]CSV template (copy and save as personnel.csv):[/bold]\n")
        console.print(content)
        console.print(
            "[dim]Columns:\n"
            "  name*                    Full name\n"
            "  email*                   Email address  (* required)\n"
            "  role                     Job title\n"
            "  tier                     standard | executive\n"
            "  platform                 android | ios\n"
            "  security_officer_email   Escalation target (executive tier)[/dim]"
        )


@app.command("export")
def export_enrolled(
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save to file"),
    include_ids: bool = typer.Option(True, "--ids/--no-ids", help="Include generated IDs"),
):
    """Export enrolled personnel list as CSV."""
    records = load_personnel()
    if not records:
        console.print("[dim]No personnel enrolled.[/dim]")
        return

    fields = ["id", "name", "email", "role", "tier", "platform", "security_officer_email", "enrolled_at"]
    if not include_ids:
        fields = [f for f in fields if f != "id"]

    buf = _io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for r in records:
        writer.writerow({f: r.get(f, "") for f in fields})

    content = buf.getvalue()

    if output:
        output.write_text(content)
        console.print(f"[ok]Exported {len(records)} records to: {output}[/ok]")
    else:
        # Write directly to stdout — no Rich formatting, safe for piping
        import sys
        sys.stdout.write(content)


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
