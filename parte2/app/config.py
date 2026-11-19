"""Configuración leída del entorno. Los valores por defecto son seguros para
pruebas; en un despliegue real hay que definir LOC_SECRET y usar HTTPS."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable


def utcnow() -> datetime:
    """UTC sin zona (naive), el formato que guarda la base de datos."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


@dataclass
class Settings:
    database_url: str = field(default_factory=lambda: os.environ.get("LOC_DATABASE_URL", "sqlite:///./parte2.db"))
    # Clave del HMAC de los códigos. Sin LOC_SECRET se genera una por proceso.
    secret: str = field(default_factory=lambda: os.environ.get("LOC_SECRET") or secrets.token_hex(32))
    code_ttl_s: int = field(default_factory=lambda: _int("LOC_CODE_TTL_S", 600))
    code_max_attempts: int = field(default_factory=lambda: _int("LOC_CODE_MAX_ATTEMPTS", 5))
    code_max_per_window: int = field(default_factory=lambda: _int("LOC_CODE_MAX_PER_WINDOW", 3))
    code_window_s: int = field(default_factory=lambda: _int("LOC_CODE_WINDOW_S", 600))
    session_device_h: int = field(default_factory=lambda: _int("LOC_SESSION_DEVICE_H", 720))
    session_viewer_h: int = field(default_factory=lambda: _int("LOC_SESSION_VIEWER_H", 12))
    retention_days: int = field(default_factory=lambda: _int("LOC_RETENTION_DAYS", 30))
    requests_per_day: int = field(default_factory=lambda: _int("LOC_REQUESTS_PER_DAY", 5))
    min_post_interval_s: int = field(default_factory=lambda: _int("LOC_MIN_POST_INTERVAL_S", 5))
    redeny_cooldown_h: int = field(default_factory=lambda: _int("LOC_REDENY_COOLDOWN_H", 24))
    # "console": escribe el SMS en el registro (laboratorio); "memory": pruebas.
    sms_backend: str = field(default_factory=lambda: os.environ.get("LOC_SMS_BACKEND", "console"))
    # SOLO demostración: devuelve el código en la respuesta. Nunca en producción.
    dev_show_code: bool = field(default_factory=lambda: os.environ.get("LOC_DEV_SHOW_CODE", "0") == "1")
    # Geocodificación inversa: vacía = desactivada (no se envían coordenadas a terceros).
    geocoder_url: str = field(default_factory=lambda: os.environ.get("LOC_GEOCODER_URL", ""))
    clock: Callable[[], datetime] = utcnow
