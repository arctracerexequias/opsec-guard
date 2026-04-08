"""Parallel source fan-out and AppRiskProfile merge."""
from __future__ import annotations
import concurrent.futures
from .base import AppRiskProfile
from .exodus import ExodusSource
from .google_play import GooglePlaySource
from .app_store import AppStoreSource
from .appcensus import AppCensusSource


def fetch_merged_profile(
    package_id: str,
    platform: str = "android",
    appcensus_key: str | None = None,
) -> AppRiskProfile | None:
    """Fan out to all sources in parallel and merge results."""
    sources = [
        ExodusSource(),
        GooglePlaySource(),
        AppStoreSource(),
        AppCensusSource(api_key=appcensus_key),
    ]

    profiles: list[AppRiskProfile] = []

    def _fetch(source):
        try:
            return source.fetch(package_id, platform)
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(_fetch, s): s for s in sources}
        for future in concurrent.futures.as_completed(futures, timeout=20):
            result = future.result()
            if result is not None:
                profiles.append(result)

    if not profiles:
        return None

    merged = profiles[0]
    for p in profiles[1:]:
        merged = merged.merge(p)

    return merged
