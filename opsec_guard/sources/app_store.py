"""
Apple App Store source — iTunes Search API (free, no auth).
Extracts: privacy nutrition labels (data linked to you / data used to track you).
"""
from __future__ import annotations
import requests
from opsec_guard.sources.base import BaseSource, AppRiskProfile
from opsec_guard.utils import cache

ITUNES_SEARCH = "https://itunes.apple.com/search"
LOOKUP_URL    = "https://itunes.apple.com/lookup"
TIMEOUT       = 10

# Privacy label categories from Apple that indicate MAID risk
TRACKING_DATA_TYPES = {
    "advertising data",
    "coarse location",
    "precise location",
    "device id",
    "user id",
    "other data",
}

LINKED_HIGH_RISK = {
    "advertising data",
    "precise location",
    "coarse location",
    "device id",
}


class AppStoreSource(BaseSource):
    name     = "app_store"
    platform = "ios"

    def fetch(self, query: str) -> AppRiskProfile | None:
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
                ITUNES_SEARCH,
                params={"term": query, "entity": "software", "limit": 5, "country": "us"},
                timeout=TIMEOUT,
            )
            if resp.status_code != 200:
                return None
            results = resp.json().get("results", [])
        except (requests.RequestException, ValueError):
            return None

        if not results:
            return None

        # Best match by name similarity
        q_lower = query.lower()
        results.sort(key=lambda r: (
            0 if q_lower in r.get("trackName", "").lower() else 1,
            -r.get("userRatingCount", 0),
        ))
        return _build_profile(results[0])

    def available(self) -> bool:
        try:
            r = requests.get(ITUNES_SEARCH, params={"term": "test", "limit": 1}, timeout=5)
            return r.status_code == 200
        except requests.RequestException:
            return False


def _build_profile(data: dict) -> AppRiskProfile:
    app_id  = str(data.get("trackId", ""))
    name    = data.get("trackName", "")
    bundle  = data.get("bundleId", "")

    # Privacy labels — available in newer API responses
    privacy = data.get("privacyDetails", {}) or {}
    used_to_track = [
        item.get("dataType", "")
        for cat in privacy.get("privacyTypes", [])
        if cat.get("privacyType") == "DATA_USED_TO_TRACK_YOU"
        for item in cat.get("dataCategories", [])
    ]
    linked_to_you = [
        item.get("dataType", "")
        for cat in privacy.get("privacyTypes", [])
        if cat.get("privacyType") == "DATA_LINKED_TO_YOU"
        for item in cat.get("dataCategories", [])
    ]
    not_linked = [
        item.get("dataType", "")
        for cat in privacy.get("privacyTypes", [])
        if cat.get("privacyType") == "DATA_NOT_LINKED_TO_YOU"
        for item in cat.get("dataCategories", [])
    ]

    maid_risk = any(t.lower() in TRACKING_DATA_TYPES for t in used_to_track) or \
                any(t.lower() in LINKED_HIGH_RISK for t in linked_to_you)

    findings = []
    if used_to_track:
        findings.append(
            f"App Store: data used to track you across apps/sites: {', '.join(used_to_track)}"
        )
    if any(t.lower() in LINKED_HIGH_RISK for t in linked_to_you):
        findings.append(
            f"App Store: high-risk data linked to identity: "
            f"{', '.join(t for t in linked_to_you if t.lower() in LINKED_HIGH_RISK)}"
        )

    all_collected = list(set(used_to_track + linked_to_you + not_linked))

    return AppRiskProfile(
        name=name,
        package=bundle or app_id,
        platform="ios",
        maid_risk=maid_risk or None,
        data_collected=all_collected,
        data_shared=used_to_track,
        findings=findings,
        sources_checked=["app_store"],
        sources_hit=["app_store"],
        raw={"app_store": {
            "trackId":       app_id,
            "trackName":     name,
            "bundleId":      bundle,
            "sellerName":    data.get("sellerName", ""),
            "primaryGenre":  data.get("primaryGenreName", ""),
            "userRatingCount": data.get("userRatingCount", 0),
        }},
    )


def _from_dict(d: dict) -> AppRiskProfile:
    p = AppRiskProfile(name=d.get("name", ""))
    for k, v in d.items():
        if hasattr(p, k):
            setattr(p, k, v)
    return p
