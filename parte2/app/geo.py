"""Cálculo geográfico y geocodificación inversa (coordenadas → dirección)."""
from __future__ import annotations

import math
import time
from functools import lru_cache
from typing import Optional

import httpx

EARTH_RADIUS_M = 6_371_008.8


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Distancia en metros sobre la esfera terrestre."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = p2 - p1
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(a)))


def inside(lat: float, lon: float, zone_lat: float, zone_lon: float, radius_m: float) -> bool:
    return haversine_m(lat, lon, zone_lat, zone_lon) <= radius_m


class Geocoder:
    """Cliente de un servicio compatible con Nominatim (`/reverse`).

    Está DESACTIVADO si no hay URL: enviar coordenadas a un tercero es una
    decisión de despliegue, no un valor por defecto. Redondea a 4 decimales
    (~11 m) antes de consultar y limita a 1 consulta por segundo, como pide la
    política de uso de Nominatim.
    """

    def __init__(self, base_url: str, client: Optional[httpx.Client] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(timeout=5.0, headers={"User-Agent": "taller2-localizacion/1.0 (academico)"})
        self._last = 0.0
        self._cache = lru_cache(maxsize=512)(self._fetch)

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)

    def reverse(self, lat: float, lon: float) -> Optional[str]:
        if not self.enabled:
            return None
        return self._cache(round(lat, 4), round(lon, 4))

    def _fetch(self, lat: float, lon: float) -> Optional[str]:
        wait = 1.0 - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        try:
            r = self._client.get(f"{self.base_url}/reverse", params={"lat": lat, "lon": lon, "format": "jsonv2"})
            r.raise_for_status()
            return r.json().get("display_name")
        except (httpx.HTTPError, ValueError):
            return None
