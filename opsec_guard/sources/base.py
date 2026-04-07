from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class AppRiskProfile:
    """Normalized risk profile aggregated from one or more sources."""
    name: str
    package: str | None = None
    platform: str = "unknown"          # android | ios | both | unknown
    risk_level: str = "unknown"        # critical | high | medium | low | unknown
    maid_risk: bool | None = None
    trackers: list[str] = field(default_factory=list)
    maid_trackers: list[str] = field(default_factory=list)   # subset known to read MAID
    permissions: list[str] = field(default_factory=list)
    data_collected: list[str] = field(default_factory=list)  # from store privacy labels
    data_shared: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)        # human-readable risk notes
    sources_checked: list[str] = field(default_factory=list)
    sources_hit: list[str] = field(default_factory=list)     # sources that returned data
    fetched_at: str = field(default_factory=lambda: datetime.now().isoformat())
    raw: dict = field(default_factory=dict)

    def merge(self, other: "AppRiskProfile") -> None:
        """Merge another profile's data into this one (non-destructive)."""
        if other.package and not self.package:
            self.package = other.package
        if other.platform != "unknown" and self.platform == "unknown":
            self.platform = other.platform
        self.trackers       = _dedup(self.trackers + other.trackers)
        self.maid_trackers  = _dedup(self.maid_trackers + other.maid_trackers)
        self.permissions    = _dedup(self.permissions + other.permissions)
        self.data_collected = _dedup(self.data_collected + other.data_collected)
        self.data_shared    = _dedup(self.data_shared + other.data_shared)
        self.findings       = _dedup(self.findings + other.findings)
        self.sources_checked = _dedup(self.sources_checked + other.sources_checked)
        self.sources_hit    = _dedup(self.sources_hit + other.sources_hit)
        self.raw.update(other.raw)
        if other.maid_risk is True:
            self.maid_risk = True
        elif other.maid_risk is False and self.maid_risk is None:
            self.maid_risk = False

    def compute_risk_level(self) -> None:
        """Derive risk_level from aggregated data."""
        score = 0
        if self.maid_risk:
            score += 40
        score += min(len(self.maid_trackers) * 15, 30)
        score += min(len(self.trackers) * 5, 20)
        if any("background" in p.lower() for p in self.permissions):
            score += 15
        if any("advertising" in d.lower() or "precise location" in d.lower()
               for d in self.data_shared):
            score += 20

        if score >= 60:
            self.risk_level = "critical"
        elif score >= 40:
            self.risk_level = "high"
        elif score >= 20:
            self.risk_level = "medium"
        elif score > 0:
            self.risk_level = "low"
        else:
            self.risk_level = "unknown"

    def to_dict(self) -> dict:
        return {
            "name":            self.name,
            "package":         self.package,
            "platform":        self.platform,
            "risk_level":      self.risk_level,
            "maid_risk":       self.maid_risk,
            "trackers":        self.trackers,
            "maid_trackers":   self.maid_trackers,
            "permissions":     self.permissions,
            "data_collected":  self.data_collected,
            "data_shared":     self.data_shared,
            "findings":        self.findings,
            "sources_checked": self.sources_checked,
            "sources_hit":     self.sources_hit,
            "fetched_at":      self.fetched_at,
        }


def _dedup(lst: list) -> list:
    seen = set()
    out = []
    for item in lst:
        key = item.lower() if isinstance(item, str) else str(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


class BaseSource(ABC):
    """Abstract base class for all external MAID data sources."""

    name: str = "base"
    platform: str = "unknown"

    @abstractmethod
    def fetch(self, query: str) -> AppRiskProfile | None:
        """
        Fetch risk data for an app by name or package ID.
        Returns None if the app is not found or the source is unavailable.
        """

    def available(self) -> bool:
        """Return True if this source is reachable / configured."""
        return True
