"""Exodus Privacy — tracker and permission analysis."""
from __future__ import annotations
import requests
from ..utils.cache import get as cache_get, set as cache_set
from .base import BaseSource, AppRiskProfile

EXODUS_API = "https://reports.exodus-privacy.eu.org/api"
MAID_TRACKER_KEYWORDS = {
    "advertising", "gaid", "idfa", "maid", "tracking", "analytics",
    "adjust", "appsflyer", "firebase", "doubleclick", "mopub",
    "applovin", "ironsource", "unity ads", "criteo", "branch",
    "bytedance", "x-mode", "outlogic", "foursquare",
}
LOCATION_PERMISSIONS = {
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
}


class ExodusSource(BaseSource):
    name = "exodus"

    def fetch(self, package_id: str, platform: str = "android") -> AppRiskProfile | None:
        if platform != "android":
            return None

        cache_key = f"exodus:{package_id}"
        cached = cache_get(cache_key)
        if cached:
            return self._parse(package_id, cached)

        try:
            resp = requests.get(
                f"{EXODUS_API}/search/{package_id}/",
                headers={"Accept": "application/json"},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return None

        if not data:
            return None

        cache_set(cache_key, data)
        return self._parse(package_id, data)

    def _parse(self, package_id: str, data: dict) -> AppRiskProfile | None:
        apps = data if isinstance(data, list) else data.get("results", [])
        if not apps:
            return None

        app = sorted(apps, key=lambda x: x.get("updated_at", ""), reverse=True)[0]
        reports = app.get("reports", [])
        if not reports:
            return None

        report = reports[0]
        trackers = report.get("trackers", [])
        permissions = report.get("permissions", [])

        tracker_names = [t.get("name", "") for t in trackers]
        is_adtech = any(
            kw in name.lower() for name in tracker_names for kw in MAID_TRACKER_KEYWORDS
        )

        has_fine_location = "ACCESS_FINE_LOCATION" in permissions
        has_bg_location = "ACCESS_BACKGROUND_LOCATION" in permissions

        risk_score = 0
        if is_adtech:
            risk_score += 40
        if has_fine_location:
            risk_score += 30
        if has_bg_location:
            risk_score += 20
        if len(trackers) > 5:
            risk_score += 10
        risk_score = min(risk_score, 100)

        return AppRiskProfile(
            app_name=app.get("name", package_id),
            package_id=package_id,
            platform="android",
            collects_maid=is_adtech,
            links_maid_to_gps=has_fine_location and is_adtech,
            background_location=has_bg_location,
            sdks=tracker_names,
            permissions=permissions,
            risk_score=risk_score,
            source="exodus",
            raw={"trackers": trackers, "permissions": permissions},
        )
