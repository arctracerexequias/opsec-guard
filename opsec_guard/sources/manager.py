"""
Source manager — fans out queries to all configured sources in parallel,
merges results into a single AppRiskProfile, and computes final risk level.
"""
from __future__ import annotations
import concurrent.futures
from opsec_guard.sources.base import AppRiskProfile, BaseSource
from opsec_guard.sources.exodus      import ExodusSource
from opsec_guard.sources.google_play import GooglePlaySource
from opsec_guard.sources.app_store   import AppStoreSource
from opsec_guard.sources.appcensus   import AppCensusSource

ALL_SOURCES: list[BaseSource] = [
    ExodusSource(),
    GooglePlaySource(),
    AppStoreSource(),
    AppCensusSource(),
]


def fetch_all(
    query: str,
    sources: list[BaseSource] | None = None,
    timeout: int = 20,
) -> AppRiskProfile:
    """
    Query all available sources in parallel.
    Returns a merged AppRiskProfile with risk_level computed.
    """
    active = sources or ALL_SOURCES
    available = [s for s in active if s.available()]

    merged = AppRiskProfile(name=query)
    merged.sources_checked = [s.name for s in active]

    if not available:
        merged.findings.append("No external sources available. Check network or configure API keys.")
        return merged

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(available)) as pool:
        future_to_source = {pool.submit(s.fetch, query): s for s in available}
        done, _ = concurrent.futures.wait(
            future_to_source, timeout=timeout,
            return_when=concurrent.futures.ALL_COMPLETED,
        )

    for future, source in future_to_source.items():
        if future not in done:
            merged.findings.append(f"{source.name}: timed out after {timeout}s")
            continue
        try:
            result = future.result()
        except Exception as exc:
            merged.findings.append(f"{source.name}: error — {exc}")
            continue

        if result is not None:
            merged.merge(result)
            if source.name not in merged.sources_hit:
                merged.sources_hit.append(source.name)

    # Use the best name found (prefer non-query strings)
    for src in ("exodus", "google_play", "app_store", "appcensus"):
        raw_name = merged.raw.get(src, {})
        candidate = (
            raw_name.get("name")
            or raw_name.get("title")
            or raw_name.get("trackName")
            or ""
        )
        if candidate and candidate.lower() != query.lower():
            merged.name = candidate
            break

    merged.compute_risk_level()
    return merged


def source_status() -> list[dict]:
    """Return availability status of all sources."""
    return [
        {
            "name":      s.name,
            "platform":  s.platform,
            "available": s.available(),
        }
        for s in ALL_SOURCES
    ]
