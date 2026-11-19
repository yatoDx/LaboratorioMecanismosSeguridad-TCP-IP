"""Reglas de negocio: consentimiento, auditoría, geofencing y retención."""
from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .config import Settings
from .geo import haversine_m, inside
from .models import (Alert, AuditLog, AuthSession, Device, Geofence, GeofenceState, Grant, Location, PhoneCode, User)


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


def audit(db: Session, now: datetime, subject_id: int, actor_phone: str, action: str, detail: str = "") -> None:
    db.add(AuditLog(at=now, subject_id=subject_id, actor_phone=actor_phone, action=action, detail=detail[:200]))


def audit_throttled(db: Session, now: datetime, subject_id: int, actor_phone: str, action: str,
                    minutes: int = 10) -> None:
    """Registra una consulta repetida a lo sumo una vez cada `minutes` minutos."""
    recent = db.scalar(select(func.count()).select_from(AuditLog).where(
        AuditLog.subject_id == subject_id, AuditLog.actor_phone == actor_phone, AuditLog.action == action,
        AuditLog.at > now - timedelta(minutes=minutes)))
    if not recent:
        audit(db, now, subject_id, actor_phone, action)


def expire_grant_if_needed(db: Session, grant: Grant, now: datetime) -> None:
    if grant.status == "approved" and grant.expires_at is not None and grant.expires_at <= now:
        grant.status = "expired"
        db.commit()


def own_grant_as_watcher(db: Session, grant_id: int, watcher_id: int, now: datetime) -> Grant:
    grant = db.get(Grant, grant_id)
    if grant is None or grant.watcher_id != watcher_id:
        raise HTTPException(404, "Solicitud no encontrada")
    expire_grant_if_needed(db, grant, now)
    return grant


def active_grant(db: Session, grant_id: int, watcher_id: int, now: datetime) -> Grant:
    """Devuelve el consentimiento solo si está aprobado y vigente."""
    grant = own_grant_as_watcher(db, grant_id, watcher_id, now)
    if grant.status != "approved":
        raise HTTPException(403, "No hay un consentimiento vigente del propietario")
    return grant


def owner_grant(db: Session, grant_id: int, owner_id: int) -> Grant:
    grant = db.get(Grant, grant_id)
    if grant is None or grant.owner_id != owner_id:
        raise HTTPException(404, "Solicitud no encontrada")
    return grant


def evaluate_geofences(db: Session, device: Device, loc: Location, previous_time: datetime | None, now: datetime) -> int:
    """Crea alertas de entrada/salida. La primera lectura solo fija el estado.
    Las lecturas antiguas (llegadas fuera de orden) no cambian el estado."""
    if previous_time is not None and loc.recorded_at < previous_time:
        return 0
    created = 0
    grants = db.scalars(select(Grant).where(Grant.owner_id == device.user_id, Grant.status == "approved",
                                            Grant.expires_at > now)).all()
    for grant in grants:
        for zone in db.scalars(select(Geofence).where(Geofence.grant_id == grant.id)):
            now_in = inside(loc.lat, loc.lon, zone.lat, zone.lon, zone.radius_m)
            state = db.get(GeofenceState, (zone.id, device.id))
            if state is None:
                db.add(GeofenceState(geofence_id=zone.id, device_id=device.id, inside=now_in))
            elif state.inside != now_in:
                state.inside = now_in
                db.add(Alert(geofence_id=zone.id, device_id=device.id, kind="enter" if now_in else "exit",
                             at=loc.recorded_at, lat=loc.lat, lon=loc.lon))
                created += 1
    return created


def path_distance_m(points: list[tuple[float, float]]) -> float:
    return sum(haversine_m(a[0], a[1], b[0], b[1]) for a, b in zip(points, points[1:]))


def purge(db: Session, settings: Settings) -> dict[str, int]:
    """Retención: borra ubicaciones y alertas antiguas, sesiones y códigos vencidos."""
    now = settings.clock()
    cutoff = now - timedelta(days=settings.retention_days)
    out = {}
    out["locations"] = db.execute(delete(Location).where(Location.recorded_at < cutoff)).rowcount
    out["alerts"] = db.execute(delete(Alert).where(Alert.at < cutoff)).rowcount
    out["sessions"] = db.execute(delete(AuthSession).where(AuthSession.expires_at < now - timedelta(days=1))).rowcount
    out["codes"] = db.execute(delete(PhoneCode).where(PhoneCode.created_at < now - timedelta(days=1))).rowcount
    out["audit"] = db.execute(delete(AuditLog).where(AuditLog.at < now - timedelta(days=365))).rowcount
    for grant in db.scalars(select(Grant).where(Grant.status == "approved", Grant.expires_at <= now)):
        grant.status = "expired"
    db.commit()
    return out


def delete_user(db: Session, user: User) -> None:
    """Derecho de supresión: borra al usuario y todo lo que cuelga de él."""
    db.execute(delete(AuditLog).where(AuditLog.subject_id == user.id))
    db.delete(user)
    db.commit()
