"""
opsec-guard maid org
Organizational and government-level MAID/geolocation OPSEC policies.
Covers: personnel policies, MDM, network controls, incident response,
and legal/compliance frameworks (PH DPA, GDPR, CCPA, ISO 27001, NIST).
"""
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from opsec_guard.utils.display import console, risk_badge


def run_org(section: str | None) -> None:
    console.print()

    sections = {
        "personnel": _personnel,
        "device":    _device,
        "network":   _network,
        "incident":  _incident,
        "legal":     _legal,
        "all":       _all,
    }

    if section is None or section == "all":
        _overview()
        return

    fn = sections.get(section.lower())
    if fn is None:
        console.print(f"[yellow]Unknown section '{section}'.[/yellow]")
        console.print("[dim]Available: personnel, device, network, incident, legal, all[/dim]")
        return

    fn()


def _overview() -> None:
    console.print(Panel.fit(
        "[bold cyan]Organizational MAID & Geolocation OPSEC[/bold cyan]\n"
        "[dim]Policy framework for government agencies, security services, and defense organizations[/dim]",
        border_style="cyan"
    ))
    console.print()

    table = Table(show_header=True, header_style="bold white", box=None, padding=(0, 2))
    table.add_column("Section",     style="bold", width=12)
    table.add_column("Command",     style="dim",  width=36)
    table.add_column("Covers")

    rows = [
        ("Personnel", "opsec-guard maid org --section personnel", "Training, device policy, role-based controls"),
        ("Device",    "opsec-guard maid org --section device",    "MDM, hardened configs, Faraday, app allowlisting"),
        ("Network",   "opsec-guard maid org --section network",   "DNS filtering, ad blocking, VPN, WiFi policy"),
        ("Incident",  "opsec-guard maid org --section incident",  "MAID exposure response, breach procedure"),
        ("Legal",     "opsec-guard maid org --section legal",     "PH DPA, GDPR, CCPA, ISO 27001, NIST"),
        ("All",       "opsec-guard maid org --section all",       "Full policy document"),
    ]
    for section, cmd, covers in rows:
        table.add_row(section, cmd, covers)

    console.print(table)
    console.print()

    # Risk summary
    console.print(Panel(
        "[bold red]Why This Matters for Government & Defense[/bold red]\n\n"
        "The Le Monde investigation (2024) demonstrated that 16 million advertising IDs — "
        "harvested passively from personal smartphones via weather apps, games, and utilities — "
        "were sufficient to:\n\n"
        "  • Identify agents of DGSI, DGSE, and GIGN by name\n"
        "  • Map their home addresses from nighttime GPS clusters\n"
        "  • Reconstruct operational movement patterns around classified facilities\n"
        "  • Expose the Élysée Palace residential security footprint\n\n"
        "No hacking was required. No warrants. No court orders.\n"
        "The data was purchased commercially for the cost of an advertising campaign.\n\n"
        "[bold]The same vulnerability applies to any government whose personnel carry\n"
        "personal smartphones with consumer apps installed.[/bold]",
        border_style="red"
    ))
    console.print()


def _personnel() -> None:
    console.print(Panel.fit(
        "[bold]Personnel Policies[/bold]", border_style="cyan"))
    console.print()

    console.print(Rule("[bold]1. Device Classification Policy[/bold]"))
    console.print()
    policies = [
        ("1.1", "Device separation",
         "Personnel in sensitive roles must use two separate physical devices:\n"
         "       (a) Work device — managed, hardened, no consumer apps.\n"
         "       (b) Personal device — kept at home or in a shielded bag during operations."),
        ("1.2", "MAID reset cadence",
         "All personnel must reset their advertising ID at minimum monthly.\n"
         "       Android 12+: delete GAID entirely. iOS: disable ATT system-wide."),
        ("1.3", "App approval list",
         "Only pre-approved applications may be installed on work devices.\n"
         "       No weather apps, games, social media, or free utilities on work devices."),
        ("1.4", "Location permission audit",
         "Quarterly audit of all app location permissions on personal devices.\n"
         "       No app should hold 'Always On' location except navigation during active use."),
        ("1.5", "Personal app disclosure",
         "Personnel must disclose use of high-risk apps (Strava, Life360, TikTok, Grindr)\n"
         "       on any device that enters secure facilities."),
    ]

    for num, title, body in policies:
        console.print(f"  [bold cyan]{num}[/bold cyan]  [bold]{title}[/bold]")
        console.print(f"       {body}")
        console.print()

    console.print(Rule("[bold]2. Awareness Training Requirements[/bold]"))
    console.print()
    training = [
        ("2.1", "Initial onboarding",    "MAID awareness briefing within 30 days of joining sensitive role."),
        ("2.2", "Annual refresher",      "Yearly training covering new broker capabilities and attack vectors."),
        ("2.3", "Incident simulation",   "Tabletop exercise: 'Your MAID appeared in a broker dataset — what now?'"),
        ("2.4", "Family awareness",      "Brief personnel families — shared household Wi-Fi can link devices."),
        ("2.5", "Travel briefing",       "Pre-travel briefing for international travel: local ad ecosystem risks."),
    ]

    for num, title, body in training:
        console.print(f"  [bold cyan]{num}[/bold cyan]  [bold]{title}[/bold]  —  {body}")

    console.print()


def _device() -> None:
    console.print(Panel.fit(
        "[bold]Device & MDM Hardening[/bold]", border_style="cyan"))
    console.print()

    console.print(Rule("[bold]3. Mobile Device Management (MDM) Controls[/bold]"))
    console.print()
    mdm = [
        ("3.1", "Enroll all work devices in MDM",
         "Use Microsoft Intune, Jamf, or equivalent. All devices must be enrolled\n"
         "       before accessing any organizational resource."),
        ("3.2", "Enforce MAID deletion via MDM",
         "Push configuration profiles that disable advertising ID at OS level.\n"
         "       iOS: restrict IDFA via MDM profile. Android: disable GAID via policy."),
        ("3.3", "App allowlisting",
         "Only MDM-approved apps may be installed. Block app store access on work devices.\n"
         "       Whitelist: Signal, approved email client, approved maps, VPN only."),
        ("3.4", "Block advertising SDK domains via MDM DNS",
         "Push DNS filtering profiles blocking known ad SDK domains:\n"
         "       doubleclick.net, admob.com, applovin.com, adjust.com, branch.io, etc."),
        ("3.5", "Disable Bluetooth and Wi-Fi scanning",
         "Push policy: Wi-Fi scanning OFF, Bluetooth scanning OFF when device is in\n"
         "       secure facility or sensitive operation mode."),
        ("3.6", "Geofence-triggered lockdown",
         "Configure MDM to enter 'restricted mode' when device enters defined\n"
         "       secure facility geofences — disabling all non-essential radios."),
    ]

    for num, title, body in mdm:
        console.print(f"  [bold cyan]{num}[/bold cyan]  [bold]{title}[/bold]")
        console.print(f"       {body}")
        console.print()

    console.print(Rule("[bold]4. Physical Controls[/bold]"))
    console.print()
    physical = [
        ("4.1", "Faraday bags / signal-blocking pouches",
         "Mandatory for all personal devices entering SCIFs or classified briefing rooms.\n"
         "       Blocks all cellular, Wi-Fi, Bluetooth, and GPS signals."),
        ("4.2", "Phone lockers at secure facility entry",
         "Physical lockers outside secure areas where personal devices are stored.\n"
         "       Not optional — enforced at entry checkpoint."),
        ("4.3", "No personal devices on operations",
         "During active field operations, personal smartphones must remain at base\n"
         "       or in Faraday containment. Work devices on operations: airplane mode\n"
         "       except when active communication is required."),
        ("4.4", "Device inspection after international travel",
         "All devices used during international travel undergo technical inspection\n"
         "       before reconnecting to organizational networks."),
    ]

    for num, title, body in physical:
        console.print(f"  [bold cyan]{num}[/bold cyan]  [bold]{title}[/bold]")
        console.print(f"       {body}")
        console.print()


def _network() -> None:
    console.print(Panel.fit(
        "[bold]Network-Level Controls[/bold]", border_style="cyan"))
    console.print()

    console.print(Rule("[bold]5. DNS Filtering & Ad Blocking[/bold]"))
    console.print()
    dns = [
        ("5.1", "Deploy Pi-hole or enterprise DNS filter",
         "Block known ad SDK, tracker, and data broker domains at network level.\n"
         "       Recommended blocklists: Steven Black, EasyList, Energized Ultimate."),
        ("5.2", "Block RTB exchange endpoints",
         "Add to DNS blocklist: openx.net, rubiconproject.com, pubmatic.com,\n"
         "       appnexus.com, smartadserver.com, mopub.com, smaato.com."),
        ("5.3", "Block data broker API endpoints",
         "Add: cuebiq.com, x-mode.io, outlogic.io, safegraph.com,\n"
         "       veraset.com, kochava.com, adjust.com, appsflyer.com."),
        ("5.4", "DNS-over-HTTPS (DoH) enforcement",
         "Enforce DoH on all devices to prevent DNS leakage and snooping.\n"
         "       Use Cloudflare 1.1.1.1 with malware/tracker filtering enabled."),
    ]

    for num, title, body in dns:
        console.print(f"  [bold cyan]{num}[/bold cyan]  [bold]{title}[/bold]")
        console.print(f"       {body}")
        console.print()

    console.print(Rule("[bold]6. VPN & Traffic Controls[/bold]"))
    console.print()
    vpn = [
        ("6.1", "Mandatory VPN on all work devices",
         "All work device traffic must route through organizational VPN.\n"
         "       This masks real IP from ad networks and prevents IP-based geolocation."),
        ("6.2", "Split tunneling disabled",
         "No split tunneling — all traffic including app traffic through VPN.\n"
         "       Prevents app SDKs from bypassing VPN to reach ad servers directly."),
        ("6.3", "Wi-Fi policy — no public networks",
         "Work devices must not connect to public or untrusted Wi-Fi.\n"
         "       Public Wi-Fi SSIDs are fingerprinting vectors."),
        ("6.4", "Cellular data only for field operations",
         "On field operations, use cellular data only. Disable Wi-Fi.\n"
         "       Wi-Fi probe requests broadcast device MAC and can be logged."),
    ]

    for num, title, body in vpn:
        console.print(f"  [bold cyan]{num}[/bold cyan]  [bold]{title}[/bold]")
        console.print(f"       {body}")
        console.print()


def _incident() -> None:
    console.print(Panel.fit(
        "[bold]Incident Response — MAID Exposure[/bold]", border_style="red"))
    console.print()

    console.print(Rule("[bold]7. MAID Exposure Detection[/bold]"))
    console.print()
    detection = [
        ("7.1", "Broker monitoring",
         "Periodically query known data broker opt-out/lookup portals for personnel MAIDs.\n"
         "       Services: Incogni, DeleteMe, or manual opt-out submissions to Cuebiq,\n"
         "       SafeGraph, Veraset, Kochava, Acxiom, LexisNexis."),
        ("7.2", "Threat intelligence feeds",
         "Subscribe to threat intel feeds that monitor dark web and broker marketplaces\n"
         "       for appearance of government-linked MAIDs or location clusters."),
        ("7.3", "Anomalous location correlation",
         "If a personnel MAID appears in ad data near classified facilities,\n"
         "       treat as a potential exposure incident — initiate response procedure."),
    ]

    for num, title, body in detection:
        console.print(f"  [bold cyan]{num}[/bold cyan]  [bold]{title}[/bold]")
        console.print(f"       {body}")
        console.print()

    console.print(Rule("[bold]8. Incident Response Procedure[/bold]"))
    console.print()
    steps = [
        "Identify the exposed MAID and the personnel linked to it.",
        "Determine which broker(s) hold the data and the date range of exposure.",
        "Immediately reset MAID on the affected device (delete GAID / disable IDFA).",
        "Submit opt-out requests to all identified brokers within 24 hours.",
        "Assess what location data was exposed: home, work, operational sites.",
        "Determine if pattern-of-life profile could have been constructed from the data.",
        "If operational security is compromised: brief leadership, adjust operational plans.",
        "If foreign actor involvement suspected: escalate to national CERT / intelligence.",
        "Document incident: MAID, exposure window, brokers involved, data scope.",
        "Review how the exposure occurred: which app/SDK was the source.",
        "Remove or restrict the source app from all personnel devices via MDM.",
        "Conduct post-incident briefing for affected personnel.",
    ]

    for i, step in enumerate(steps, 1):
        console.print(f"  [bold cyan]{i:02d}[/bold cyan]  {step}")

    console.print()


def _legal() -> None:
    console.print(Panel.fit(
        "[bold]Legal & Compliance Framework[/bold]", border_style="cyan"))
    console.print()

    console.print(Rule("[bold]9. Philippine Data Privacy Act (RA 10173)[/bold]"))
    console.print()
    console.print(
        "  The [bold]Data Privacy Act of 2012 (Republic Act 10173)[/bold] governs the collection,\n"
        "  processing, and storage of personal information in the Philippines, enforced by the\n"
        "  [bold]National Privacy Commission (NPC)[/bold].\n"
    )

    ph_provisions = [
        ("9.1", "Consent requirement",
         "Collection of personal data — including MAIDs and location data — requires\n"
         "       freely given, specific, informed, and unambiguous consent (Sec. 3(b)).\n"
         "       Buried consent in app ToS does not satisfy this standard under NPC guidelines."),
        ("9.2", "Data minimization",
         "Only data strictly necessary for the declared purpose may be collected (Sec. 11).\n"
         "       An app whose stated purpose is weather forecasting cannot lawfully collect\n"
         "       continuous GPS data for advertising without separate explicit consent."),
        ("9.3", "Purpose limitation",
         "Data collected for one purpose cannot be used for another without new consent.\n"
         "       Selling MAID+GPS to data brokers is a secondary purpose — requires separate consent."),
        ("9.4", "Right to erasure",
         "Data subjects have the right to demand deletion of their personal data (Sec. 16(c)).\n"
         "       This extends to MAID-linked location histories held by data brokers."),
        ("9.5", "Security obligations",
         "Organizations must implement appropriate safeguards. Failure to prevent\n"
         "       unauthorized MAID data collection by embedded SDKs may constitute a violation."),
        ("9.6", "National security exception",
         "Government agencies may process data without consent for national security,\n"
         "       public order, or public safety purposes (Sec. 7(b)) — but only to the extent\n"
         "       necessary and with appropriate legal authorization."),
        ("9.7", "NPC complaint mechanism",
         "Individuals can file complaints with the NPC at complaints@privacy.gov.ph\n"
         "       or via the NPC website. Violations carry penalties of PHP 500K–5M + imprisonment."),
    ]

    for num, title, body in ph_provisions:
        console.print(f"  [bold cyan]{num}[/bold cyan]  [bold]{title}[/bold]")
        console.print(f"       {body}")
        console.print()

    console.print(Rule("[bold]10. Global Compliance Frameworks[/bold]"))
    console.print()

    frameworks = [
        ("GDPR\n(EU)",
         "Lawful basis required for MAID processing. Explicit opt-in for location data.\n"
         "       Right to erasure, data portability. Fines up to 4% global annual revenue.\n"
         "       Applies to any app used by EU residents — including Philippine-developed apps\n"
         "       with EU users."),
        ("CCPA / CPRA\n(California, USA)",
         "Right to opt out of sale of personal data including MAIDs.\n"
         "       Applies to companies doing business with California residents.\n"
         "       Data brokers must register with California AG and honor opt-out requests."),
        ("PIPEDA\n(Canada)",
         "Consent required for collection of location data. Meaningful consent —\n"
         "       not buried in fine print. Right to access and correct personal data."),
        ("PDPA\n(Thailand / Singapore)",
         "Similar to GDPR. Consent required for sensitive data including location.\n"
         "       Relevant for regional operations across Southeast Asia."),
        ("ISO/IEC 27001",
         "International standard for information security management systems (ISMS).\n"
         "       Organizations handling sensitive personnel data should be ISO 27001 certified.\n"
         "       Annex A.8 covers asset management including mobile device controls."),
        ("NIST SP 800-124\n(Mobile Device Security)",
         "US NIST guidelines for enterprise mobile device security.\n"
         "       Covers MDM deployment, app vetting, and network security for mobile devices.\n"
         "       Widely adopted as a baseline even outside the US government context."),
        ("NATO INFOSEC\nGuidelines",
         "For defense-aligned organizations: NATO INFOSEC guidelines restrict\n"
         "       personal device use in sensitive environments and mandate device separation\n"
         "       for personnel with access to classified information."),
    ]

    table = Table(show_header=True, header_style="bold white", box=None, padding=(0, 2))
    table.add_column("Framework", style="bold", width=18)
    table.add_column("Key Requirements for MAID / Location Data")

    for framework, reqs in frameworks:
        table.add_row(framework, reqs)

    console.print(table)
    console.print()

    console.print(Rule("[bold]11. Defense Procurement & Responsible Disclosure[/bold]"))
    console.print()
    console.print(
        "  When presenting MAID exposure capabilities to government as a defensive service:\n"
    )
    disclosure = [
        ("11.1", "Responsible disclosure framework",
         "Document the vulnerability, affected scope, and evidence before approaching government.\n"
         "       Follow coordinated disclosure norms — brief the affected agency before public release."),
        ("11.2", "Legal authorization",
         "Obtain written authorization before conducting any MAID lookups or broker queries\n"
         "       on behalf of government personnel. Operating without authorization may violate\n"
         "       the Cybercrime Prevention Act of 2012 (RA 10175) in the Philippines."),
        ("11.3", "Defense procurement process",
         "Government procurement in the Philippines follows [bold]RA 9184 (Government Procurement\n"
         "       Reform Act)[/bold]. Engage via:\n"
         "       (a) PhilGEPS registration for government supplier accreditation\n"
         "       (b) Direct contracting is allowed for national security / intelligence services\n"
         "           under Sec. 50 of RA 9184 when competitive bidding would compromise security\n"
         "       (c) Consider partnering with a registered Philippine defense contractor"),
        ("11.4", "Data handling during pilot",
         "Any MAID or location data accessed during a pilot engagement must be:\n"
         "       (a) handled under a signed NDA and data processing agreement\n"
         "       (b) stored only on systems within Philippine jurisdiction\n"
         "       (c) deleted upon contract completion unless retention is authorized in writing"),
        ("11.5", "Export control awareness",
         "Surveillance and intelligence software may be subject to export control regulations.\n"
         "       Check Wassenaar Arrangement Category 5 Part 2 (Information Security) for\n"
         "       any components involving interception, monitoring, or collection capabilities."),
    ]

    for num, title, body in disclosure:
        console.print(f"  [bold cyan]{num}[/bold cyan]  [bold]{title}[/bold]")
        console.print(f"       {body}")
        console.print()


def _all() -> None:
    _overview()
    _personnel()
    _device()
    _network()
    _incident()
    _legal()
