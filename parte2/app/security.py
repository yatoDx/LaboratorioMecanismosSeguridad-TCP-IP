"""Primitivas de seguridad: normalización de teléfono, códigos, tokens y SMS."""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets

log = logging.getLogger("localizacion.sms")

_E164 = re.compile(r"^\+[1-9]\d{7,14}$")


def normalize_phone(raw: str) -> str:
    """Acepta '+57 300 123 4567' o '+57-300-123-4567'; exige formato E.164 con '+'."""
    phone = re.sub(r"[\s\-().]", "", raw or "")
    if not _E164.match(phone):
        raise ValueError("El número debe estar en formato internacional, por ejemplo +573001234567")
    return phone


def new_code() -> str:
    """6 dígitos de un generador criptográfico (no `random`)."""
    return f"{secrets.randbelow(10**6):06d}"


def code_hmac(secret: str, phone: str, code: str) -> str:
    return hmac.new(secret.encode(), f"{phone}:{code}".encode(), hashlib.sha256).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class SmsBackend:
    """Interfaz de envío. En producción se sustituye por un proveedor real
    (Twilio, etc.); aquí no se envía nada a la red."""

    def send(self, phone: str, text: str) -> None:  # pragma: no cover - interfaz
        raise NotImplementedError


class ConsoleSms(SmsBackend):
    def send(self, phone: str, text: str) -> None:
        log.warning("SMS simulado a %s: %s", phone, text)


class MemorySms(SmsBackend):
    """Guarda los mensajes para que las pruebas lean el código."""

    def __init__(self) -> None:
        self.outbox: list[tuple[str, str]] = []

    def send(self, phone: str, text: str) -> None:
        self.outbox.append((phone, text))

    def last_code(self, phone: str) -> str:
        for p, t in reversed(self.outbox):
            if p == phone:
                return re.search(r"\b(\d{6})\b", t).group(1)
        raise LookupError(phone)
