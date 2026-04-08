"""Base types and abstract source class."""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class AppRiskProfile:
    app_name: str
    package_id: str
    platform: str  # android | ios | both
    collects_maid: bool | None = None
    links_maid_to_gps: bool | None = None
    gps_precision_meters: int | None = None
    background_location: bool | None = None
    rtb_participant: bool | None = None
    maid_fallback_fingerprinting: bool | None = None
    sdks: list[str] = field(default_factory=list)
    brokers: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    risk_score: int | None = None
    source: str = "local"
    raw: dict = field(default_factory=dict)

    def merge(self, other: "AppRiskProfile") -> "AppRiskProfile":
        """Merge another profile into this one, preferring non-None values."""
        def pick(a, b):
            return a if a is not None else b

        return AppRiskProfile(
            app_name=self.app_name or other.app_name,
            package_id=self.package_id,
            platform=self.platform,
            collects_maid=pick(self.collects_maid, other.collects_maid),
            links_maid_to_gps=pick(self.links_maid_to_gps, other.links_maid_to_gps),
            gps_precision_meters=pick(self.gps_precision_meters, other.gps_precision_meters),
            background_location=pick(self.background_location, other.background_location),
            rtb_participant=pick(self.rtb_participant, other.rtb_participant),
            maid_fallback_fingerprinting=pick(
                self.maid_fallback_fingerprinting, other.maid_fallback_fingerprinting
            ),
            sdks=list(set(self.sdks + other.sdks)),
            brokers=list(set(self.brokers + other.brokers)),
            permissions=list(set(self.permissions + other.permissions)),
            risk_score=pick(self.risk_score, other.risk_score),
            source=f"{self.source}+{other.source}",
            raw={**other.raw, **self.raw},
        )


class BaseSource(ABC):
    name: str = "base"

    @abstractmethod
    def fetch(self, package_id: str, platform: str = "android") -> AppRiskProfile | None:
        """Fetch risk profile for a given app package ID."""
        ...
