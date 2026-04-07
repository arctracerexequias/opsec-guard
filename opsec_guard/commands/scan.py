import json
import subprocess
from pathlib import Path
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from opsec_guard.utils.display import console, risk_badge

DATA_DIR = Path(__file__).parent.parent / "data"

# Known risky packages cross-referenced with apps.json
RISKY_PACKAGES = {
    "com.weather.Weather":              ("The Weather Channel", "high"),
    "com.accuweather.android":          ("AccuWeather",         "high"),
    "com.wunderground.android.weather": ("Weather Underground",  "medium"),
    "gbis.gbandroid":                   ("GasBuddy",             "high"),
    "com.bitsmedia.android.muslimpro":  ("Muslim Pro",           "critical"),
    "com.life360.android.safetymapd":   ("Life360",              "critical"),
    "com.strava":                       ("Strava",               "high"),
    "com.grindrapp.android":            ("Grindr",               "critical"),
    "com.zhiliaoapp.musically":         ("TikTok",               "high"),
    "com.facebook.katana":              ("Facebook",             "high"),
    "com.facebook.orca":                ("Messenger",            "high"),
    "com.instagram.android":            ("Instagram",            "high"),
    "com.king.candycrushsaga":          ("Candy Crush Saga",     "medium"),
    "com.truecaller":                   ("Truecaller",           "high"),
    "com.mt.mtxx.mtxx":                 ("Meitu",                "high"),
    "com.flightradar24free":            ("Flightradar24",        "medium"),
    "com.joelapenna.foursquared":       ("Foursquare",           "high"),
    "com.zynga.words":                  ("Words With Friends",   "medium"),
}

# Permissions that indicate MAID/location data collection
SENSITIVE_PERMISSIONS = {
    "android.permission.ACCESS_FINE_LOCATION":          ("Precise GPS",         "high"),
    "android.permission.ACCESS_COARSE_LOCATION":        ("Approximate Location","medium"),
    "android.permission.ACCESS_BACKGROUND_LOCATION":    ("Background Location", "critical"),
    "android.permission.READ_PHONE_STATE":              ("Device Identifiers",  "high"),
    "android.permission.ACCESS_WIFI_STATE":             ("Wi-Fi Scanning",      "medium"),
    "android.permission.CHANGE_NETWORK_STATE":          ("Network State",       "low"),
    "android.permission.BLUETOOTH_SCAN":                ("Bluetooth Scanning",  "medium"),
    "com.google.android.gms.permission.AD_ID":          ("Ad ID (MAID)",        "high"),
}


def _run_adb(args: list[str], device_id: str | None = None) -> str | None:
    cmd = ["adb"]
    if device_id:
        cmd += ["-s", device_id]
    cmd += args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _get_devices() -> list[str]:
    output = _run_adb(["devices"])
    if not output:
        return []
    lines = output.splitlines()[1:]
    return [l.split()[0] for l in lines if "device" in l and "offline" not in l]


def _get_packages(device_id: str | None) -> list[str]:
    output = _run_adb(["shell", "pm", "list", "packages", "-3"], device_id)
    if not output:
        return []
    return [l.replace("package:", "").strip() for l in output.splitlines() if l.startswith("package:")]


def _get_permissions(package: str, device_id: str | None) -> list[str]:
    output = _run_adb(["shell", "dumpsys", "package", package], device_id)
    if not output:
        return []
    granted = []
    in_runtime = False
    for line in output.splitlines():
        stripped = line.strip()
        if "granted=true" in stripped:
            for perm in SENSITIVE_PERMISSIONS:
                if perm in stripped:
                    granted.append(perm)
    return list(set(granted))


def run_scan(device_id: str | None) -> None:
    console.print()

    # Check ADB availability
    if _run_adb(["version"]) is None:
        console.print(Panel(
            "[yellow]ADB not found.[/yellow]\n\n"
            "To use the scan command, install ADB:\n"
            "  [bold]sudo apt install adb[/bold]\n\n"
            "Then enable [bold]Developer Options → USB Debugging[/bold] on your Android device\n"
            "and connect it via USB.",
            border_style="yellow"
        ))
        return

    devices = _get_devices()
    if not devices:
        console.print(Panel(
            "[yellow]No Android device detected.[/yellow]\n\n"
            "Make sure your device is:\n"
            "  1. Connected via USB\n"
            "  2. Developer Options enabled\n"
            "  3. USB Debugging enabled\n"
            "  4. You have authorized this computer on the device",
            border_style="yellow"
        ))
        return

    target = device_id or devices[0]
    if target not in devices:
        console.print(f"[red]Device '{target}' not found. Available: {', '.join(devices)}[/red]")
        return

    console.print(f"[dim]Scanning device: [bold]{target}[/bold][/dim]")
    console.print(f"[dim]Retrieving installed packages...[/dim]")

    packages = _get_packages(target)
    if not packages:
        console.print("[red]Could not retrieve package list. Check ADB authorization.[/red]")
        return

    console.print(f"[dim]Found {len(packages)} third-party packages. Cross-referencing...[/dim]")
    console.print()

    hits = []
    for pkg in packages:
        if pkg in RISKY_PACKAGES:
            name, risk = RISKY_PACKAGES[pkg]
            perms = _get_permissions(pkg, target)
            hits.append({"package": pkg, "name": name, "risk": risk, "granted_permissions": perms})

    console.print(Rule(f"[bold]Scan Results — {target}[/bold]"))
    console.print()

    if not hits:
        console.print(Panel.fit(
            f"[green]No known high-risk apps found[/green] among {len(packages)} installed packages.\n\n"
            "[dim]This only checks against documented apps. Unknown apps may still embed\n"
            "advertising SDKs. Review your installed apps manually for SDK disclosures.[/dim]",
            border_style="green"
        ))
        return

    # Sort by risk severity
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    hits.sort(key=lambda x: order.get(x["risk"], 4))

    console.print(f"  Found [bold red]{len(hits)}[/bold red] risky app(s) out of {len(packages)} installed:\n")

    table = Table(show_header=True, header_style="bold white", box=None, padding=(0, 2))
    table.add_column("App",          style="bold")
    table.add_column("Package",      style="dim")
    table.add_column("Risk")
    table.add_column("Sensitive Permissions Granted")

    for h in hits:
        perm_labels = []
        for p in h["granted_permissions"]:
            if p in SENSITIVE_PERMISSIONS:
                label, severity = SENSITIVE_PERMISSIONS[p]
                color = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "dim"}.get(severity, "white")
                perm_labels.append(f"[{color}]{label}[/{color}]")

        perm_str = ", ".join(perm_labels) if perm_labels else "[dim]None confirmed[/dim]"
        table.add_row(h["name"], h["package"], risk_badge(h["risk"]), perm_str)

    console.print(table)
    console.print()

    critical_count = sum(1 for h in hits if h["risk"] == "critical")
    high_count     = sum(1 for h in hits if h["risk"] == "high")

    if critical_count > 0:
        console.print(f"  [bold red]{critical_count} CRITICAL[/bold red] app(s) detected — immediate action recommended.")
    if high_count > 0:
        console.print(f"  [bold orange1]{high_count} HIGH[/bold orange1] risk app(s) detected.")

    console.print()
    console.print("[dim]Run [bold]opsec-guard maid reset[/bold] to reset your advertising ID and revoke unnecessary location permissions.[/dim]")
    console.print()
