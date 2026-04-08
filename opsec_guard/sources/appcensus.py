"""AppCensus — dynamic analysis of app network traffic."""
from __future__ import annotations
import requests
from ..utils.cache import get as cache_get, set as cache_set
from .base import BaseSource, AppRiskProfile

APPCENSUS_API = "https://api.appcensus.io/v1"


class AppCensusSource(BaseSource):
    name = "appcensus"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key

    def fetch(self, package_id: str, platform: str = "android") -> AppRiskProfile | None:
        if not self.api_key:
            return None

        cache_key = f"appcensus:{platform}:{package_id}"
        cached = cache_get(cache_key)
        if cached:
            return self._parse(package_id, platform, cached)

        try:
            resp = requests.get(
                f"{APPCENSUS_API}/apps/{package_id}",
                headers={"Authorization": f"Bearer {self.api_key}"},
                params={"platform": platform},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.HTTPError as e:
            if e.response.status_code in (404, 403):
                return None
            return None
        except Exception:
            return None

        cache_set(cache_key, data)
        return self._parse(package_id, platform, data)

    def _parse(self, package_id: str, platform: str, data: dict) -> AppRiskProfile:
        behaviors = data.get("behaviors", [])
        transmits_maid = any(
            b.get("type") in ("maid_transmission", "advertising_id") for b in behaviors
        )
        transmits_location = any(
            b.get("type") in ("location_transmission", "gps_transmission") for b in behaviors
        )
        fingerprinting = any(b.get("type") == "fingerprinting" for b in behaviors)

        risk_score = 0
        if transmits_maid:
            risk_score += 40
        if transmits_location:
            risk_score += 35
        if fingerprinting:
            risk_score += 25
        risk_score = min(risk_score, 100)

        return AppRiskProfile(
            app_name=data.get("app_name", package_id),
            package_id=package_id,
            platform=platform,
            collects_maid=transmits_maid,
            links_maid_to_gps=transmits_maid and transmits_location,
            maid_fallback_fingerprinting=fingerprinting,
            risk_score=risk_score,
            source="appcensus",
            raw=data,
        )
