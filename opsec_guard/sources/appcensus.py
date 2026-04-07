"""
AppCensus source — https://appcheck.appcensus.io
Dynamic analysis: observes actual network traffic from apps in a sandbox.
Detects real MAID transmissions (not just declared/static analysis).
Requires a free API key from https://appcensus.io
"""
from __future__ import annotations
import requests
from pathlib import Path
from opsec_guard.sources.base import BaseSource, AppRiskProfile
from opsec_guard.utils import cache
from opsec_guard.utils.storage import STORAGE_DIR

API_BASE    = "https://api.appcensus.io/v1"
TIMEOUT     = 15
CONFIG_PATH = STORAGE_DIR / "appcensus_key.txt"

# AppCensus behavior tags that directly indicate MAID transmission
MAID_BEHAVIORS = {
    "advertising_id_transmitted",
    "idfa_transmitted",
    "gaid_transmitted",
    "maid_transmitted",
}

LOCATION_BEHAVIORS = {
    "precise_location_transmitted",
    "gps_transmitted",
    "location_to_third_party",
}


def load_api_key() -> str | None:
    if CONFIG_PATH.exists():
        return CONFIG_PATH.read_text().strip() or None
    import os
    return os.environ.get("APPCENSUS_API_KEY")


def save_api_key(key: str) -> None:
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(key.strip())


class AppCensusSource(BaseSource):
    name     = "appcensus"
    platform = "both"

    def __init__(self) -> None:
        self._key = load_api_key()

    def available(self) -> bool:
        return self._key is not None

    def fetch(self, query: str) -> AppRiskProfile | None:
        if not self.available():
            return None

        cached = cache.get(self.name, query)
        if cached:
            return _from_dict(cached)

        profile = self._search(query)
        if profile:
            cache.set(self.name, query, profile.to_dict())
        return profile

    def _search(self, query: str) -> AppRiskProfile | None:
        try:
            resp = requests.get(
                f"{API_BASE}/search",
                params={"q": query, "limit": 5},
                headers={"Authorization": f"Bearer {self._key}",
                         "Accept": "application/json"},
                timeout=TIMEOUT,
            )
            if resp.status_code == 401:
                return None  # bad key
            if resp.status_code != 200:
                return None
            results = resp.json().get("results", [])
        except (requests.RequestException, ValueError):
            return None

        if not results:
            return None

        app = results[0]
        return self._get_analysis(app)

    def _get_analysis(self, app: dict) -> AppRiskProfile | None:
        app_id = app.get("id") or app.get("app_id")
        if not app_id:
            return None

        try:
            resp = requests.get(
                f"{API_BASE}/analysis/{app_id}",
                headers={"Authorization": f"Bearer {self._key}",
                         "Accept": "application/json"},
                timeout=TIMEOUT,
            )
            if resp.status_code != 200:
                return _profile_from_meta(app)
            analysis = resp.json()
        except (requests.RequestException, ValueError):
            return _profile_from_meta(app)

        return _build_profile(app, analysis)


def _profile_from_meta(app: dict) -> AppRiskProfile:
    return AppRiskProfile(
        name=app.get("title", app.get("package", "")),
        package=app.get("package"),
        platform=app.get("platform", "unknown"),
        sources_checked=["appcensus"],
        sources_hit=["appcensus"],
        raw={"appcensus": app},
    )


def _build_profile(app: dict, analysis: dict) -> AppRiskProfile:
    name    = app.get("title", app.get("package", ""))
    package = app.get("package", "")

    behaviors    = {b.lower() for b in analysis.get("behaviors", [])}
    destinations = analysis.get("data_destinations", [])   # third parties receiving data
    tracker_list = analysis.get("trackers_detected", [])

    maid_transmitted     = bool(behaviors & MAID_BEHAVIORS)
    location_transmitted = bool(behaviors & LOCATION_BEHAVIORS)
    maid_risk            = maid_transmitted or location_transmitted

    findings = []
    if maid_transmitted:
        findings.append(
            "AppCensus (dynamic): MAID/advertising ID transmission observed in live network traffic."
        )
    if location_transmitted:
        findings.append(
            "AppCensus (dynamic): precise GPS location transmitted to third-party server."
        )
    if destinations:
        dest_names = [d.get("domain", d.get("name", "")) for d in destinations[:5]]
        findings.append(
            f"AppCensus: data transmitted to: {', '.join(filter(None, dest_names))}"
        )

    return AppRiskProfile(
        name=name,
        package=package,
        platform=app.get("platform", "unknown"),
        maid_risk=maid_risk or None,
        trackers=tracker_list,
        maid_trackers=[t for t in tracker_list if any(
            m in t.lower() for m in ("admob", "facebook", "applovin", "adjust",
                                      "branch", "kochava", "appsflyer", "x-mode")
        )],
        findings=findings,
        sources_checked=["appcensus"],
        sources_hit=["appcensus"],
        raw={"appcensus": {"app": app, "behaviors": list(behaviors)}},
    )


def _from_dict(d: dict) -> AppRiskProfile:
    p = AppRiskProfile(name=d.get("name", ""))
    for k, v in d.items():
        if hasattr(p, k):
            setattr(p, k, v)
    return p
