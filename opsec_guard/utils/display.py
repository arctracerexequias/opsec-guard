"""Rich console helpers."""
from rich.console import Console
from rich.theme import Theme

THEME = Theme({
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "yellow",
    "low": "green",
    "info": "cyan",
    "exec": "bold magenta",
    "ok": "bold green",
    "warn": "bold orange3",
    "title": "bold white",
    "dim": "dim white",
})

console = Console(theme=THEME)


def risk_color(level: str) -> str:
    mapping = {
        "Critical": "critical",
        "High": "high",
        "Medium": "medium",
        "Low": "low",
    }
    return mapping.get(level, "white")


def score_color(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def tier_badge(tier: str) -> str:
    if tier == "executive":
        return "[exec]★ EXECUTIVE[/exec]"
    return "[info]● STANDARD[/info]"


# Backwards compat aliases used by old code in repo
def risk_badge(level: str) -> str:
    badges = {
        "critical": "[bold red][ CRITICAL ][/bold red]",
        "high": "[bold yellow][ HIGH     ][/bold yellow]",
        "medium": "[yellow][ MEDIUM   ][/yellow]",
        "low": "[green][ LOW      ][/green]",
    }
    return badges.get(level.lower(), f"[white][ {level.upper()} ][/white]")


def score_to_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"
