"""Google Play Store — app permissions and data safety labels."""
from __future__ import annotations
from ..utils.cache import get as cache_get, set as cache_set
from .base import BaseSource, AppRiskProfile


class GooglePlaySource(BaseSource):
    name = "google_play"

    def fetch(self, package_id: str, platform: str = "android") -> AppRiskProfile | None:
        if platform != "android":
            return None

        cache_key = f"gplay:{package_id}"
        cached = cache_get(cache_key)
        if cached:
            return self._parse(package_id, cached)

        try:
            from google_play_scraper import app as gplay_app, permissions
            details = gplay_app(package_id, lang="en", country="ph")
            try:
                perms = permissions(package_id, lang="en")
                all_perms = [p for group in perms.values() for p in group] if perms else []
            except Exception:
                all_perms = []
            data = {**details, "_permissions": all_perms}
            cache_set(cache_key, data)
        except ImportError:
            return None
        except Exception:
            return None

        return self._parse(package_id, data)

    def _parse(self, package_id: str, data: dict) -> AppRiskProfile:
        permissions_list = data.get("_permissions", [])
        has_fine_loc = "ACCESS_FINE_LOCATION" in permissions_list
        has_bg_loc = "ACCESS_BACKGROUND_LOCATION" in permissions_list
        has_ad_id = "READ_ADVERTISING_ID" in permissions_list or "AD_ID" in permissions_list

        risk_score = 0
        if has_fine_loc:
            risk_score += 30
        if has_bg_loc:
            risk_score += 25
        if has_ad_id:
            risk_score += 20
        risk_score = min(risk_score, 100)

        return AppRiskProfile(
            app_name=data.get("title", package_id),
            package_id=package_id,
            platform="android",
            collects_maid=has_ad_id or risk_score >= 40,
            links_maid_to_gps=has_fine_loc and (has_ad_id or risk_score >= 40),
            background_location=has_bg_loc,
            permissions=permissions_list,
            risk_score=risk_score,
            source="google_play",
            raw=data,
        )
