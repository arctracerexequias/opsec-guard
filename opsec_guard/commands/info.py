from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from opsec_guard.utils.display import console


def run_info() -> None:
    console.print()
    console.print(Panel.fit(
        "[bold cyan]What is a MAID?[/bold cyan]",
        border_style="cyan"
    ))

    console.print("""
A [bold]Mobile Advertising ID (MAID)[/bold] is a unique, resettable identifier built into every
smartphone. It exists in two forms:

  [bold cyan]Android[/bold cyan]  →  [bold]GAID[/bold] (Google Advertising ID)  — found in Settings > Google > Ads
  [bold cyan]iOS[/bold cyan]      →  [bold]IDFA[/bold] (Identifier for Advertisers)  — found in Settings > Privacy > Tracking

MAIDs were designed to replace non-resettable hardware identifiers (like IMEI) for
advertising purposes, allowing users to opt out or reset. In practice, however, they
have become the primary key used to build persistent surveillance profiles.
""")

    console.print(Panel.fit("[bold]How MAIDs Are Exploited[/bold]", border_style="dim"))

    steps = [
        ("1. Collection", "An app (weather, game, flashlight) embeds a third-party SDK. That SDK reads your MAID and your precise GPS coordinates — often in the background."),
        ("2. Enrichment", "The MAID+GPS pair is timestamped and sent to a data broker (Cuebiq, X-Mode, SafeGraph). The broker correlates it with hundreds of other apps doing the same."),
        ("3. Profiling",  "After a few days, your MAID has a full movement history: home address (where you sleep), work address (where you stay 8h/day), religious sites, medical visits, military/government locations."),
        ("4. Sale",       "This profile is sold in bulk or via real-time APIs to advertisers, hedge funds, law enforcement, and intelligence agencies — often without a warrant."),
        ("5. Re-ID",      "Even after you reset your MAID, brokers use device fingerprinting (screen size, OS version, battery state, WiFi MACs) to re-link your new MAID to your old profile."),
    ]

    for title, body in steps:
        console.print(f"  [bold cyan]{title}[/bold cyan]")
        console.print(f"  {body}")
        console.print()

    console.print(Panel.fit("[bold]Real-World Incidents[/bold]", border_style="dim"))

    table = Table(show_header=True, header_style="bold white", box=None, padding=(0, 2))
    table.add_column("Year", style="dim", width=6)
    table.add_column("Incident")
    table.add_column("Impact", style="dim")

    incidents = [
        ("2018", "NYT: Weather Channel / GasBuddy sold MAID+GPS to hedge funds", "40M+ US devices"),
        ("2018", "Strava heatmap exposed patrol routes of intelligence/military personnel", "Global military bases"),
        ("2019", "FTC complaint vs The Weather Channel for covert MAID+GPS monetization", "Millions of users"),
        ("2020", "Muslim Pro sold MAID data to X-Mode → US military contractors", "98M app downloads"),
        ("2020", "Babel Street 'Locate X' used by Secret Service to track individuals", "Law enforcement use"),
        ("2020", "Venntel sold MAID location to DHS/ICE bypassing warrant requirements", "$2M govt contract"),
        ("2021", "Life360 sold MAID+GPS of 31M users incl. children to data brokers", "3 major brokers"),
        ("2021", "SafeGraph sold abortion clinic visitor data; removed from Google Cloud", "Reproductive rights"),
        ("2022", "FTC sued Kochava for selling MAID data exposing sensitive site visits", "Reproductive health"),
        ("2024", "Le Monde: 16M French advertising IDs linked to intelligence/military GPS", "DGSI, DGSE, GIGN"),
    ]

    for year, incident, impact in incidents:
        table.add_row(year, incident, impact)

    console.print(table)
    console.print()

    console.print(Panel.fit("[bold]The RTB Ecosystem — How Your MAID Reaches Hundreds of Buyers[/bold]",
                            border_style="dim"))
    console.print("""
Every time a mobile app loads an ad, a [bold]real-time bidding (RTB) auction[/bold] runs in under
100 milliseconds. The auction broadcast — called a [bold]bid request[/bold] — contains your MAID,
precise GPS coordinates, the app you're using, and behavioral data.

This broadcast is sent [bold red]simultaneously to 200–500 ad buyers[/bold red]. Every buyer who
receives it — whether they win the auction or not — now has your MAID+GPS data point.

  [dim]App loads ad → SDK sends bid request → Exchange broadcasts to 500 DSPs[/dim]
  [dim]→ All 500 receive your MAID+GPS → Brokers harvest this stream → Sold commercially[/dim]

A single user generating 100 ad impressions per day exposes their MAID to
[bold]thousands of companies per week[/bold] without any interaction.

This is how the Le Monde investigation obtained [bold]16 million French advertising IDs[/bold]
with complete movement histories — not by hacking, but by harvesting the RTB bid stream.
""")

    console.print(Panel.fit("[bold]Zero-Click Ad Malware — The Silent Attack Vector[/bold]",
                            border_style="red"))
    console.print("""
Once a threat actor has your MAID (from a broker purchase or RTB bid stream), they can
deliver malware to your device [bold red]without you clicking anything[/bold red].

[bold]How it works:[/bold]
  1. Attacker registers as an advertiser on a DSP platform.
  2. Creates a malicious ad containing exploit code for a known WebView vulnerability.
  3. Bids to serve the ad specifically to your MAID via RTB.
  4. When your app loads the ad, the exploit executes silently in the background.
  5. Payload can install spyware: keylogger, microphone/camera access, location tracking.

[bold]Why this is critical for high-value targets:[/bold]
  • No phishing link to click — fully passive
  • Bypasses traditional security awareness training
  • Nation-state actors have used this vector against government officials and journalists
  • Keeping OS and apps updated is the primary mitigation
  • iOS [bold]Lockdown Mode[/bold] significantly reduces the attack surface for at-risk individuals

Run [bold cyan]opsec-guard maid techniques zero-click[/bold cyan] for full technical detail.
""")

    console.print(Panel.fit("[bold]Why Resetting Your MAID Matters[/bold]", border_style="dim"))
    console.print("""
Resetting your MAID breaks the existing linkage in broker databases — your movement
history can no longer be attributed to you by MAID lookup alone.

However, [bold red]it is not a complete solution[/bold red]:
  • Brokers use [bold]device fingerprinting[/bold] to re-link new MAIDs to old profiles
  • SDKs may collect IP address, WiFi BSSID, and hardware IDs as fallback identifiers
  • The only robust mitigation is [bold]limiting which apps receive location permission[/bold]

Run [bold cyan]opsec-guard maid reset[/bold cyan] for step-by-step instructions on your platform.
Run [bold cyan]opsec-guard maid audit[/bold cyan] to assess your current exposure level.
Run [bold cyan]opsec-guard maid techniques[/bold cyan] for the full technical ecosystem breakdown.
Run [bold cyan]opsec-guard maid org[/bold cyan] for organizational and government-level policies.
""")
