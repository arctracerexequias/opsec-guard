"""Organizational OPSEC policies and legal compliance framework."""
import typer
from rich.panel import Panel
from ..utils.display import console

app = typer.Typer(help="OPSEC policies and compliance framework.")


@app.command("policy")
def show_policy():
    """Display the organizational MAID OPSEC policy."""
    console.print(
        Panel(
            "[bold]MAID OPSEC Policy — Protected Personnel Program[/bold]\n\n"
            "This policy applies to all personnel enrolled in the OpsecGuard program.\n\n"
            "[info]1. Device Classification[/info]\n"
            "  • Work Device:    MDM-managed, approved apps only, no personal social media\n"
            "  • Executive Device: Dedicated device, quarterly audit, Lockdown Mode/GrapheneOS\n"
            "  • Personal Device: Not permitted in classified meetings or secure areas\n\n"
            "[info]2. Mandatory Controls[/info]\n"
            "  • MAID must be reset monthly (executives: weekly)\n"
            "  • Background Location must be denied to all non-essential apps\n"
            "  • TikTok, Facebook, and non-approved ad-supported apps are prohibited on work devices\n"
            "  • VPN (WireGuard) must be active on all cellular connections\n"
            "  • OS and apps must be fully updated within 72h of security patch release\n\n"
            "[info]3. Sensitive Location Protocol[/info]\n"
            "  • Enable Airplane Mode before entering: govt offices, boardrooms, secure facilities\n"
            "  • Enable Airplane Mode during: classified briefings, sensitive negotiations\n"
            "  • Reset MAID immediately after visiting any flagged location\n"
            "  • Bluetooth and WiFi OFF when transiting through airports\n\n"
            "[info]4. Executive-Specific Controls[/info]\n"
            "  • Dedicated work device — never used for personal apps\n"
            "  • Quarterly broker opt-out campaign\n"
            "  • Security officer receives all high-priority alerts\n"
            "  • Annual device replacement or factory reset recommended\n"
            "  • iOS: Lockdown Mode enabled | Android: GrapheneOS recommended\n\n"
            "[info]5. Incident Response[/info]\n"
            "  • Any flagged-zone alert → notify security officer immediately\n"
            "  • Suspected device compromise → isolate device, contact SOC\n"
            "  • Zero-click malware suspected → full device wipe, do not back up\n",
            title="[title]MAID OPSEC Policy[/title]",
            border_style="yellow",
        )
    )


@app.command("compliance")
def show_compliance():
    """Show legal compliance framework for this program."""
    console.print(
        Panel(
            "[bold]Legal Compliance Framework[/bold]\n\n"
            "[info]Republic of the Philippines[/info]\n"
            "  • RA 10173 (Data Privacy Act of 2012)\n"
            "    - Sec. 12(a): Consent as lawful basis — obtained at enrollment\n"
            "    - Sec. 34: Data Subject Rights — right to erasure via `enroll remove`\n"
            "    - Sec. 21: Security of personal data — AES-256 encryption at rest\n"
            "    - NPC Circular 2023-04: Data breach notification (72h)\n"
            "  • RA 9184 (Government Procurement Reform Act) — for govt deployments\n"
            "  • RA 10175 (Cybercrime Prevention Act) — prohibits unauthorized interception\n\n"
            "[info]European Union[/info]\n"
            "  • GDPR Art. 6(1)(a): Explicit consent — obtained at enrollment\n"
            "  • GDPR Art. 17: Right to Erasure — implemented via `enroll remove`\n"
            "  • GDPR Art. 25: Privacy by design — minimum data collection\n"
            "  • GDPR Art. 32: Technical security measures — encryption, access control\n"
            "  • ePrivacy Directive: MAID tracking requires consent\n\n"
            "[info]United States[/info]\n"
            "  • CCPA/CPRA: Right to opt out of data sale — broker campaign implements this\n"
            "  • FTC Act Sec. 5: Unfair/deceptive practices — applies to broker data use\n\n"
            "[info]International Standards[/info]\n"
            "  • ISO/IEC 27001: Information security management — access control, encryption\n"
            "  • NIST SP 800-124 Rev. 2: Mobile Device Security Guidelines\n"
            "    - MDM enrollment for managed devices\n"
            "    - App vetting and allowlisting\n"
            "  • NATO INFOSEC Policy (MC 0571/1): Mobile device restrictions in NATO facilities\n\n"
            "[warn]Important:[/warn]\n"
            "  This program is authorized for defensive security purposes only.\n"
            "  Use for surveillance, tracking without consent, or offensive intelligence\n"
            "  collection is prohibited and may violate RA 10175, GDPR Art. 82, and\n"
            "  could constitute an unlawful act under PH Revised Penal Code Art. 290.\n",
            title="[title]Legal Compliance[/title]",
            border_style="green",
        )
    )
