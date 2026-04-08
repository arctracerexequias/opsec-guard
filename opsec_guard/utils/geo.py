"""Geolocation utilities — flagged location detection."""
import json
import math
from pathlib import Path

FLAGGED_LOCATIONS_FILE = Path(__file__).parent.parent / "data" / "flagged_locations.json"


def _load_flagged() -> list[dict]:
    try:
        return json.loads(FLAGGED_LOCATIONS_FILE.read_text())
    except Exception:
        return []


def haversine_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Distance between two GPS coordinates in meters."""
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def check_flagged_locations(lat: float, lon: float) -> list[dict]:
    """Return any flagged locations within their defined radius of the given coordinates."""
    matches = []
    for loc in _load_flagged():
        dist = haversine_meters(lat, lon, loc["lat"], loc["lon"])
        if dist <= loc["radius_meters"]:
            matches.append({**loc, "distance_meters": round(dist, 1)})
    return matches


def is_in_flagged_zone(lat: float, lon: float) -> bool:
    return len(check_flagged_locations(lat, lon)) > 0
