"""Apple App Store — iTunes Search API + privacy nutrition labels."""
from __future__ import annotations
import requests
from ..utils.cache import get as cache_get, set as cache_set
from .base import BaseSource, AppRiskProfile

ITUNES_SEARCH = "https://itunes.apple.com/lookup"


class AppStoreSource(BaseSource):
    name = "app_store"

    def fetch(self, package_id: str, platform: str = "ios") -> AppRiskProfile | None:
        if platform not in ("ios", "both"):
            return None

        cache_key = f"appstore:{package_id}"
        cached = cache_get(cache_key)
        if cached:
            return self._parse(package_id, cached)

        try:
            resp = requests.get(
                ITUNES_SEARCH,
                params={"bundleId": package_id, "entity": "software"},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])
            if not results:
                return None
            app_data = results[0]
            cache_set(cache_key, app_data)
        except Exception:
            return None

        return self._parse(package_id, app_data)

    def _parse(self, package_id: str, data: dict) -> AppRiskProfile:
        privacy_types = data.get("privacyTypes", [])
        all_data_types = []
        for pt in privacy_types:
            for item in pt.get("dataTypes", []):
                all_data_types.append(
                    f"{pt.get('privacyType', '').upper()}.{item.get('dataType', '').upper()}"
                )

        tracks_location = any("LOCATION" in dt for dt in all_data_types)
        tracks_identifiers = any("IDENTIFIER" in dt for dt in all_data_types)
        linked_to_you = any("LINKED_TO_YOU" in dt for dt in all_data_types)
        used_to_track = any("USED_TO_TRACK" in dt for dt in all_data_types)

        risk_score = 0
        if tracks_location:
            risk_score += 30
        if tracks_identifiers:
            risk_score += 25
        if linked_to_you:
            risk_score += 25
        if used_to_track:
            risk_score += 20
        risk_score = min(risk_score, 100)

        return AppRiskProfile(
            app_name=data.get("trackName", package_id),
            package_id=package_id,
            platform="ios",
            collects_maid=tracks_identifiers or used_to_track,
            links_maid_to_gps=tracks_location and tracks_identifiers,
            risk_score=risk_score,
            source="app_store",
            raw={"privacy_types": privacy_types, "data_types": all_data_types},
        )
