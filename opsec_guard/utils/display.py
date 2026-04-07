from rich.console import Console
from rich.theme import Theme

THEME = Theme({
    "critical": "bold red",
    "high":     "bold orange1",
    "medium":   "bold yellow",
    "low":      "bold green",
    "info":     "bold cyan",
    "muted":    "dim white",
})

console = Console(theme=THEME)

RISK_COLORS = {
    "critical": "red",
    "high":     "orange1",
    "medium":   "yellow",
    "low":      "green",
}

RISK_BADGES = {
    "critical": "[bold red][ CRITICAL ][/bold red]",
    "high":     "[bold orange1][ HIGH     ][/bold orange1]",
    "medium":   "[bold yellow][ MEDIUM   ][/bold yellow]",
    "low":      "[bold green][ LOW      ][/bold green]",
}

SCORE_LEVELS = [
    (75, "critical"),
    (50, "high"),
    (25, "medium"),
    (0,  "low"),
]


def risk_badge(level: str) -> str:
    return RISK_BADGES.get(level.lower(), f"[white][ {level.upper()} ][/white]")


def score_to_level(score: int) -> str:
    for threshold, level in SCORE_LEVELS:
        if score >= threshold:
            return level
    return "low"


def banner() -> None:
    console.print()
    console.print("  [bold cyan]opsec[/bold cyan][bold white]-[/bold white][bold red]guard[/bold red]  "
                  "[dim]v0.1.0[/dim]")
    console.print("  [dim]MAID exposure auditing & mobile geolocation privacy tool[/dim]")
    console.print()
