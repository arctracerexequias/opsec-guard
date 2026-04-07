"""
Google Play Store source — uses google-play-scraper (PyPI).
Extracts: data safety section, declared permissions, app metadata.
No API key required.
"""
from __future__ import annotations
from opsec_guard.sources.base import BaseSource, AppRiskProfile
from opsec_guard.utils import cache

# Data safety categories from Google Play that indicate MAID/location risk
MAID_DATA_TYPES = {
    "device or other ids",
    "advertising id",
    "precise location",
    "approximate location",
}

SHARED_DATA_HIGH_RISK = {
    "advertising or marketing",
    "analytics",
    "third-party advertising",
}


class GooglePlaySource(BaseSource):
    name     = "google_play"
    platform = "android"

    def __init__(self) -> None:
        self._available: bool | None = None

    def available(self) -> bool:
        if self._available is None:
            try:
                import google_play_scraper  # noqa: F401
                self._available = True
            except ImportError:
                self._available = False
        return self._available

    def fetch(self, query: str) -> AppRiskProfile | None:
        if not self.available():
            return None

        cached = cache.get(self.name, query)
        if cached:
            return _from_dict(cached)

        profile = self._fetch_by_id(query) or self._fetch_by_search(query)
        if profile:
            cache.set(self.name, query, profile.to_dict())
        return profile

    def _fetch_by_id(self, package: str) -> AppRiskProfile | None:
        if "." not in package:
            return None
        try:
            from google_play_scraper import app
            data = app(package, lang="en", country="us")
            return _build_profile(data)
        except Exception:
            return None

    def _fetch_by_search(self, name: str) -> AppRiskProfile | None:
        try:
            from google_play_scraper import search
            results = search(name, n_hits=3, lang="en", country="us")
            if not results:
                return None
            # Best match = first result
            from google_play_scraper import app
            data = app(results[0]["appId"], lang="en", country="us")
            return _build_profile(data)
        except Exception:
            return None


def _build_profile(data: dict) -> AppRiskProfile:
    package    = data.get("appId", "")
    name       = data.get("title", package)
    permissions = data.get("permissions", []) or []

    # Data safety section (newer Play Store field)
    data_safety = data.get("dataSafety", {}) or {}
    collected   = []
    shared      = []

    for item in data_safety.get("dataCollected", []):
        cat = item.get("category", "").lower()
        collected.append(item.get("category", ""))
        if cat in MAID_DATA_TYPES:
            collected.append(f"[MAID-linked] {item.get('category', '')}")

    for item in data_safety.get("dataShared", []):
        cat = item.get("category", "").lower()
        purpose = item.get("purposes", [])
        shared.append(item.get("category", ""))
        for p in purpose:
            if p.lower() in SHARED_DATA_HIGH_RISK:
                shared.append(f"[HIGH-RISK share] {item.get('category','')} → {p}")

    # Infer MAID risk
    maid_risk = any(
        d.lower() in MAID_DATA_TYPES or "advertising id" in d.lower()
        for d in collected + shared
    )

    findings = []
    if maid_risk:
        findings.append("Google Play data safety: declares collection/sharing of advertising ID or precise location.")
    if any("advertising" in s.lower() for s in shared):
        findings.append("Google Play: data shared for advertising/marketing purposes — typical MAID broker pipeline.")

    # Sensitive permissions from Play (if returned)
    sensitive_perms = [p for p in permissions if any(k in str(p).upper() for k in
        ["LOCATION", "PHONE_STATE", "AD_ID", "BLUETOOTH_SCAN", "WIFI_STATE"])]

    return AppRiskProfile(
        name=name,
        package=package,
        platform="android",
        maid_risk=maid_risk or None,
        permissions=sensitive_perms,
        data_collected=[c for c in collected if "[MAID-linked]" not in c],
        data_shared=[s for s in shared if "[HIGH-RISK share]" not in s],
        findings=findings,
        sources_checked=["google_play"],
        sources_hit=["google_play"],
        raw={"google_play": {
            "appId": package,
            "title": name,
            "developer": data.get("developer", ""),
            "score": data.get("score"),
            "installs": data.get("installs"),
        }},
    )


def _from_dict(d: dict) -> AppRiskProfile:
    p = AppRiskProfile(name=d.get("name", ""))
    for k, v in d.items():
        if hasattr(p, k):
            setattr(p, k, v)
    return p
