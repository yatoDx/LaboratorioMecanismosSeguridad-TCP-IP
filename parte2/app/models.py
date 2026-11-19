"""Esquema de la base de datos (SQLAlchemy 2.0; SQLite por defecto, PostgreSQL por URL)."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    """Persona con un número telefónico verificado. Solo se guarda el número."""
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    phone: Mapped[str] = mapped_column(String(20), unique=True, index=True)  # E.164
    created_at: Mapped[datetime] = mapped_column(DateTime)
    devices: Mapped[list["Device"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class PhoneCode(Base):
    """Código de verificación. Nunca se guarda en claro: solo su HMAC."""
    __tablename__ = "phone_codes"
    id: Mapped[int] = mapped_column(primary_key=True)
    phone: Mapped[str] = mapped_column(String(20), index=True)
    code_hmac: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)


class Device(Base):
    """Instalación de la app en un teléfono. El dueño controla si comparte."""
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("user_id", "label"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    label: Mapped[str] = mapped_column(String(40))
    sharing_enabled: Mapped[bool] = mapped_column(Boolean, default=False)  # apagado hasta que el dueño lo active
    interval_s: Mapped[int] = mapped_column(Integer, default=600)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    user: Mapped[User] = relationship(back_populates="devices")
    locations: Mapped[list["Location"]] = relationship(back_populates="device", cascade="all, delete-orphan")


class AuthSession(Base):
    """Token de acceso. Se guarda solo el SHA-256; el token viaja una vez."""
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(10))  # "device" | "viewer"
    device_id: Mapped[Optional[int]] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class Grant(Base):
    """Consentimiento: el dueño (owner) autoriza a un observador (watcher)."""
    __tablename__ = "grants"
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    watcher_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(10))  # pending|approved|denied|revoked|expired
    requested_at: Mapped[datetime] = mapped_column(DateTime)
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    share_history: Mapped[bool] = mapped_column(Boolean, default=False)
    message: Mapped[str] = mapped_column(String(140), default="")
    owner: Mapped[User] = relationship(foreign_keys=[owner_id])
    watcher: Mapped[User] = relationship(foreign_keys=[watcher_id])


class Location(Base):
    __tablename__ = "locations"
    __table_args__ = (Index("ix_loc_device_time", "device_id", "recorded_at"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    lat: Mapped[float] = mapped_column(Float)
    lon: Mapped[float] = mapped_column(Float)
    accuracy_m: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime)
    received_at: Mapped[datetime] = mapped_column(DateTime)
    source: Mapped[str] = mapped_column(String(10), default="periodic")  # periodic | manual
    device: Mapped[Device] = relationship(back_populates="locations")


class Geofence(Base):
    """Zona definida por un observador sobre un consentimiento vigente."""
    __tablename__ = "geofences"
    id: Mapped[int] = mapped_column(primary_key=True)
    grant_id: Mapped[int] = mapped_column(ForeignKey("grants.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(40))
    lat: Mapped[float] = mapped_column(Float)
    lon: Mapped[float] = mapped_column(Float)
    radius_m: Mapped[float] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime)


class GeofenceState(Base):
    __tablename__ = "geofence_states"
    geofence_id: Mapped[int] = mapped_column(ForeignKey("geofences.id", ondelete="CASCADE"), primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True)
    inside: Mapped[bool] = mapped_column(Boolean)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    geofence_id: Mapped[int] = mapped_column(ForeignKey("geofences.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(5))  # enter | exit
    at: Mapped[datetime] = mapped_column(DateTime)
    lat: Mapped[float] = mapped_column(Float)
    lon: Mapped[float] = mapped_column(Float)


class AuditLog(Base):
    """Registro de transparencia: el dueño ve quién pidió y quién consultó."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime)
    subject_id: Mapped[int] = mapped_column(Integer, index=True)  # persona afectada (sin FK: sobrevive al borrado)
    actor_phone: Mapped[str] = mapped_column(String(20))
    action: Mapped[str] = mapped_column(String(30))
    detail: Mapped[str] = mapped_column(String(200), default="")
