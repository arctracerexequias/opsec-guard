"""
Exodus Privacy source — https://exodus-privacy.eu.org
Free public API. No authentication required.
Provides static analysis of Android APKs: embedded trackers and permissions.
"""
from __future__ import annotations
import requests
from opsec_guard.sources.base import BaseSource, AppRiskProfile
from opsec_guard.utils import cache

BASE_URL  = "https://reports.exodus-privacy.eu.org/api"
TIMEOUT   = 10

# Trackers in Exodus known to read/transmit MAIDs
MAID_TRACKERS = {
    "admob", "google ads", "google firebase analytics",
    "facebook ads", "facebook analytics", "facebook login",
    "applovin", "applovin max", "ironsource", "unity ads",
    "mopub", "twitter mopub",
    "adjust", "branch", "appsflyer", "kochava",
    "braze", "leanplum",
    "foursquare pilgrim", "cuebiq", "x-mode", "outlogic",
    "inmobi", "verizon media", "oath",
    "snap audience network", "snapchat",
    "chartboost", "vungle",
}


def _is_maid_tracker(tracker_name: str) -> bool:
    name_lower = tracker_name.lower()
    return any(t in name_lower for t in MAID_TRACKERS)


class ExodusSource(BaseSource):
    name     = "exodus"
    platform = "android"

    def fetch(self, query: str) -> AppRiskProfile | None:
        cached = cache.get(self.name, query)
        if cached:
            return _from_dict(cached)

        # Try treating query as package name first, then as search term
        profile = self._by_package(query) or self._by_search(query)
        if profile:
            cache.set(self.name, query, profile.to_dict())
        return profile

    def _by_package(self, package: str) -> AppRiskProfile | None:
        # Exodus search endpoint accepts package names
        if "." not in package:
            return None
        return self._search(package)

    def _by_search(self, name: str) -> AppRiskProfile | None:
        return self._search(name)

    def _search(self, query: str) -> AppRiskProfile | None:
        try:
            resp = requests.get(
                f"{BASE_URL}/search",
                params={"query": query},
                timeout=TIMEOUT,
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
        except (requests.RequestException, ValueError):
            return None

        apps = data.get("apps", [])
        if not apps:
            return None

        # Pick the best match (most reports)
        app = sorted(apps, key=lambda a: a.get("number_of_reports", 0), reverse=True)[0]
        return self._get_report(app)

    def _get_report(self, app: dict) -> AppRiskProfile | None:
        handle = app.get("handle", "")
        name   = app.get("name", handle)

        try:
            resp = requests.get(
                f"{BASE_URL}/report/{handle}",
                timeout=TIMEOUT,
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                # Fall back to app-level data only
                return _profile_from_app(app)
            report_data = resp.json()
        except (requests.RequestException, ValueError):
            return _profile_from_app(app)

        return _profile_from_report(name, handle, report_data)

    def available(self) -> bool:
        try:
            r = requests.get(f"{BASE_URL}/trackers", timeout=5,
                             headers={"Accept": "application/json"})
            return r.status_code == 200
        except requests.RequestException:
            return False


def _profile_from_app(app: dict) -> AppRiskProfile:
    handle = app.get("handle", "")
    name   = app.get("name", handle)
    return AppRiskProfile(
        name=name,
        package=handle,
        platform="android",
        sources_checked=["exodus"],
        sources_hit=["exodus"],
        raw={"exodus": app},
    )


def _profile_from_report(name: str, package: str, data: dict) -> AppRiskProfile:
    # Latest report is the most recent version
    reports = data.get("reports", [{}])
    latest  = reports[0] if reports else {}

    trackers     = [t.get("name", "") for t in latest.get("trackers", [])]
    permissions  = latest.get("permissions", [])
    maid_t       = [t for t in trackers if _is_maid_tracker(t)]
    maid_risk    = len(maid_t) > 0

    findings = []
    if maid_t:
        findings.append(f"Exodus: contains {len(maid_t)} MAID-reading tracker(s): {', '.join(maid_t)}")
    if any("ACCESS_BACKGROUND_LOCATION" in p for p in permissions):
        findings.append("Exodus: requests ACCESS_BACKGROUND_LOCATION — can harvest GPS in background")
    if any("READ_PHONE_STATE" in p for p in permissions):
        findings.append("Exodus: requests READ_PHONE_STATE — can read IMEI and device identifiers")
    if any("AD_ID" in p for p in permissions):
        findings.append("Exodus: explicitly requests AD_ID permission — direct MAID access declared")

    return AppRiskProfile(
        name=name,
        package=package,
        platform="android",
        maid_risk=maid_risk,
        trackers=trackers,
        maid_trackers=maid_t,
        permissions=permissions,
        findings=findings,
        sources_checked=["exodus"],
        sources_hit=["exodus"],
        raw={"exodus": data},
    )


def _from_dict(d: dict) -> AppRiskProfile:
    p = AppRiskProfile(name=d.get("name", ""))
    for k, v in d.items():
        if hasattr(p, k):
            setattr(p, k, v)
    return p
