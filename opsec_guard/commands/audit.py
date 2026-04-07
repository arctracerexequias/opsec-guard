import typer
from datetime import datetime
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from opsec_guard.utils.display import console, risk_badge, score_to_level
from opsec_guard.utils.storage import save_audit
from opsec_guard.utils.alerts import send_critical_alert, load_config


# Each question: (key, prompt, options, weights)
# weight maps option index → score contribution
QUESTIONS: list[dict] = [
    {
        "key": "platform",
        "prompt": "Which mobile platform do you primarily use?",
        "options": ["Android", "iOS", "Both", "Other/None"],
        "weights": [0, 0, 0, 0],  # informational only
    },
    {
        "key": "maid_reset_frequency",
        "prompt": "How often do you reset your MAID (GAID / IDFA)?",
        "options": [
            "Never — I didn't know this was a thing",
            "Rarely (less than once a year)",
            "A few times a year",
            "Monthly",
            "Weekly or more",
        ],
        "weights": [20, 15, 10, 4, 0],
    },
    {
        "key": "ad_tracking_opt_out",
        "prompt": "Have you disabled ad tracking / opted out of ads personalization on your device?",
        "options": [
            "No",
            "Yes, but I'm not sure if it's fully applied",
            "Yes, fully disabled (Android 12 deleted GAID / iOS ATT off)",
        ],
        "weights": [15, 7, 0],
    },
    {
        "key": "weather_apps",
        "prompt": "Do you use a weather app with location access? (e.g. The Weather Channel, AccuWeather, Weather Underground)",
        "options": [
            "Yes, with 'Always' / background location",
            "Yes, with 'While Using' location only",
            "Yes, but location is denied",
            "No",
        ],
        "weights": [15, 6, 1, 0],
    },
    {
        "key": "fitness_apps",
        "prompt": "Do you use fitness or activity tracking apps with GPS? (e.g. Strava, Nike Run Club, Garmin Connect)",
        "options": [
            "Yes, with always-on / background GPS",
            "Yes, only active during workouts",
            "No",
        ],
        "weights": [12, 4, 0],
    },
    {
        "key": "mobile_games",
        "prompt": "Do you play free-to-play mobile games with ads?",
        "options": [
            "Yes, multiple games",
            "Yes, one or two",
            "No",
        ],
        "weights": [8, 4, 0],
    },
    {
        "key": "social_apps",
        "prompt": "Do you have Facebook, TikTok, or Instagram installed with location access?",
        "options": [
            "Yes, one or more with location enabled",
            "Yes, installed but location denied",
            "No",
        ],
        "weights": [10, 3, 0],
    },
    {
        "key": "free_vpn",
        "prompt": "Do you use a free VPN app?",
        "options": [
            "Yes",
            "No",
        ],
        "weights": [12, 0],
    },
    {
        "key": "background_location",
        "prompt": "How many apps on your phone have 'Always' / background location access?",
        "options": [
            "5 or more",
            "2–4 apps",
            "1 app",
            "None",
        ],
        "weights": [15, 8, 3, 0],
    },
    {
        "key": "sideloading",
        "prompt": "Do you install apps from outside the official app store (sideloading / APKs)?",
        "options": [
            "Yes, regularly",
            "Occasionally",
            "Never",
        ],
        "weights": [10, 5, 0],
    },
    {
        "key": "sensitive_role",
        "prompt": "Do you work in a sensitive role? (law enforcement, intelligence, military, government, journalism, activism, legal)",
        "options": [
            "Yes",
            "No",
        ],
        "weights": [0, 0],  # no score contribution, but adds warning in report
    },
    {
        "key": "work_personal_same_device",
        "prompt": "Do you use the same phone for both sensitive work and personal apps?",
        "options": [
            "Yes",
            "No, separate devices",
        ],
        "weights": [8, 0],
    },
    {
        "key": "wifi_scanning",
        "prompt": "Have you disabled Wi-Fi and Bluetooth scanning in location settings? (Android: Settings → Location → Wi-Fi scanning)",
        "options": [
            "No / I haven't checked",
            "Yes",
            "Not on Android",
        ],
        "weights": [5, 0, 0],
    },
]

MAX_SCORE = sum(max(q["weights"]) for q in QUESTIONS)


def _ask(question: dict, index: int, total: int) -> tuple[int, str]:
    console.print(f"\n[bold cyan][{index}/{total}][/bold cyan] {question['prompt']}")
    for i, opt in enumerate(question["options"], 1):
        console.print(f"  [dim]{i}.[/dim] {opt}")

    while True:
        raw = typer.prompt("  Your choice", default="").strip()
        if raw.isdigit():
            choice = int(raw)
            if 1 <= choice <= len(question["options"]):
                return choice - 1, question["options"][choice - 1]
        console.print("  [red]Please enter a number from the list.[/red]")


def run_audit(save: bool) -> None:
    console.print()
    console.print(Panel.fit(
        "[bold cyan]MAID Exposure Audit[/bold cyan]\n"
        "[dim]Answer honestly — results are stored locally only.[/dim]",
        border_style="cyan"
    ))

    answers: dict[str, dict] = {}
    total_score = 0
    total_qs = len(QUESTIONS)

    for i, q in enumerate(QUESTIONS, 1):
        idx, label = _ask(q, i, total_qs)
        score_contrib = q["weights"][idx]
        total_score += score_contrib
        answers[q["key"]] = {
            "answer_index": idx,
            "answer_label": label,
            "score_contribution": score_contrib,
        }

    # Normalize to 0–100
    normalized = round((total_score / MAX_SCORE) * 100) if MAX_SCORE > 0 else 0
    level = score_to_level(normalized)
    sensitive = answers.get("sensitive_role", {}).get("answer_index", 1) == 0

    console.print()
    console.print(Rule("[bold]Audit Results[/bold]"))
    console.print()

    console.print(f"  Exposure Score : [bold]{normalized}/100[/bold]  {risk_badge(level)}")
    console.print()

    # Score breakdown table
    table = Table(show_header=True, header_style="bold white", box=None, padding=(0, 2))
    table.add_column("Factor", style="bold")
    table.add_column("Your Answer", style="dim")
    table.add_column("Score", justify="right")

    for q in QUESTIONS:
        key = q["key"]
        a = answers[key]
        contrib = a["score_contribution"]
        max_c = max(q["weights"])
        color = "red" if contrib == max_c and max_c > 0 else ("yellow" if contrib > 0 else "green")
        table.add_row(
            q["prompt"][:55] + ("…" if len(q["prompt"]) > 55 else ""),
            a["answer_label"][:40] + ("…" if len(a["answer_label"]) > 40 else ""),
            f"[{color}]+{contrib}[/{color}]",
        )

    console.print(table)
    console.print()

    # Recommendations
    console.print(Rule("[bold]Top Recommendations[/bold]"))
    console.print()
    _print_recommendations(answers, sensitive)

    if sensitive:
        console.print()
        console.print(Panel(
            "[bold red]Sensitive Role Detected[/bold red]\n\n"
            "Given your role, MAID-linked geolocation exposure is a direct operational security risk.\n"
            "Consider:\n"
            "  • A dedicated work device with no advertising apps installed\n"
            "  • Leaving personal phone at home or in a Faraday bag during sensitive operations\n"
            "  • Enforcing MDM policies that block advertising SDKs at the network level\n"
            "  • Reviewing TSCM (Technical Surveillance Counter-Measures) guidance from your org",
            border_style="red"
        ))

    result = {
        "timestamp": datetime.now().isoformat(),
        "score": normalized,
        "level": level,
        "sensitive_role": sensitive,
        "answers": answers,
        "max_score": MAX_SCORE,
        "raw_score": total_score,
    }

    if save:
        path = save_audit(result)
        console.print(f"\n[dim]Audit saved to {path}[/dim]")
        console.print("[dim]Run [bold]opsec-guard maid report[/bold] to generate a full report.[/dim]")
    else:
        console.print()
        console.print("[dim]Tip: re-run with [bold]--save[/bold] to store results and generate a report later.[/dim]")

    # Auto-send alert if critical or high and alert config exists
    if level in ("critical", "high") and load_config() is not None:
        from opsec_guard.commands.report import _generate_findings
        findings = _generate_findings(answers, sensitive)
        if findings:
            console.print()
            console.print(f"[bold red]Sending {level.upper()} alert email...[/bold red]")
            ok, msg = send_critical_alert(findings, normalized, level)
            if ok:
                console.print(f"[green]{msg}[/green]")
            else:
                console.print(f"[yellow]Alert not sent: {msg}[/yellow]")
    elif level in ("critical", "high"):
        console.print()
        console.print(f"[dim]Tip: configure alert emails with [bold]opsec-guard maid alerts configure[/bold] "
                      f"to automatically receive notifications on {level.upper()} results.[/dim]")

    console.print()


def _print_recommendations(answers: dict, sensitive: bool) -> None:
    recs = []

    if answers["maid_reset_frequency"]["answer_index"] <= 1:
        recs.append(("[orange1]Reset your MAID now[/orange1]",
                     "You've never or rarely reset it. Run [bold]opsec-guard maid reset[/bold] for steps."))

    if answers["ad_tracking_opt_out"]["answer_index"] == 0:
        recs.append(("[red]Enable ad tracking opt-out[/red]",
                     "Android 12+: delete your GAID entirely. iOS: disable ATT in Settings → Privacy → Tracking."))

    if answers["weather_apps"]["answer_index"] == 0:
        recs.append(("[red]Revoke background location from your weather app[/red]",
                     "Weather apps are the #1 vector for MAID+GPS harvesting. Switch to 'While Using' or deny."))

    if answers["background_location"]["answer_index"] <= 1:
        recs.append(("[orange1]Audit background location permissions[/orange1]",
                     "Go through Settings → Location (Android) or Settings → Privacy → Location (iOS) and revoke 'Always' from non-essential apps."))

    if answers["free_vpn"]["answer_index"] == 0:
        recs.append(("[red]Uninstall free VPN apps[/red]",
                     "Free VPNs commonly monetize through data brokerage. Use a paid, audited VPN (Mullvad, ProtonVPN) or none at all."))

    if answers["social_apps"]["answer_index"] == 0:
        recs.append(("[orange1]Deny location to social apps[/orange1]",
                     "Facebook and TikTok embed MAIDs in their advertising SDKs used by thousands of other apps."))

    if answers["wifi_scanning"]["answer_index"] == 0:
        recs.append(("[yellow]Disable Wi-Fi and Bluetooth scanning[/yellow]",
                     "These allow location inference even with GPS/location off. Android: Settings → Location → Wi-Fi scanning → OFF."))

    if answers["work_personal_same_device"]["answer_index"] == 0 and sensitive:
        recs.append(("[red]Use separate devices for work and personal use[/red]",
                     "A single device mixing sensitive work and ad-SDK-embedded personal apps is a critical OPSEC failure point."))

    if not recs:
        console.print("  [green]Your practices look solid. Keep resetting your MAID regularly.[/green]")
        return

    for title, body in recs:
        console.print(f"  • {title}")
        console.print(f"    [dim]{body}[/dim]")
        console.print()
