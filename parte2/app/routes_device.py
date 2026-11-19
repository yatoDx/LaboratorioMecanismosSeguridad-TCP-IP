"""App del dispositivo (la persona que comparte su ubicación)."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .deps import Principal, db_dep, device_principal
from .models import AuditLog, Device, Geofence, Grant, Location, User
from .schemas import ApproveIn, LocationIn, SharingIn
from .services import audit, evaluate_geofences, iso, owner_grant

router = APIRouter(prefix="/api/device", tags=["dispositivo"])


def _grant_row(g: Grant, watcher: User) -> dict:
    return {"id": g.id, "watcher_phone": watcher.phone, "status": g.status, "message": g.message,
            "requested_at": iso(g.requested_at), "decided_at": iso(g.decided_at),
            "expires_at": iso(g.expires_at), "share_history": g.share_history}


@router.get("/status")
def status(request: Request, p: Principal = Depends(device_principal), db: Session = Depends(db_dep)):
    now = request.app.state.settings.clock()
    d = p.device
    grants = db.scalars(select(Grant).where(Grant.owner_id == p.user.id).order_by(Grant.id.desc()).limit(50)).all()
    for g in grants:  # marca como vencidos los consentimientos pasados de fecha
        if g.status == "approved" and g.expires_at <= now:
            g.status = "expired"
    db.commit()
    rows = [_grant_row(g, g.watcher) for g in grants]
    zones = []
    for g in grants:
        if g.status == "approved":
            for z in db.scalars(select(Geofence).where(Geofence.grant_id == g.id)):
                zones.append({"id": z.id, "name": z.name, "radius_m": z.radius_m, "watcher_phone": g.watcher.phone})
    return {"phone": p.user.phone,
            "device": {"id": d.id, "label": d.label, "sharing_enabled": d.sharing_enabled,
                       "interval_s": d.interval_s, "last_seen_at": iso(d.last_seen_at)},
            "requests": [r for r in rows if r["status"] == "pending"],
            "grants": [r for r in rows if r["status"] != "pending"],
            "geofences": zones}


@router.put("/sharing")
def set_sharing(body: SharingIn, request: Request, p: Principal = Depends(device_principal),
                db: Session = Depends(db_dep)):
    now = request.app.state.settings.clock()
    d = p.device
    d.sharing_enabled = body.enabled
    if body.interval_s is not None:
        d.interval_s = body.interval_s
    audit(db, now, p.user.id, p.user.phone, "sharing_on" if body.enabled else "sharing_off", f"cada {d.interval_s}s")
    db.commit()
    return {"sharing_enabled": d.sharing_enabled, "interval_s": d.interval_s}


@router.post("/locations", status_code=201)
def post_location(body: LocationIn, request: Request, p: Principal = Depends(device_principal),
                  db: Session = Depends(db_dep)):
    s = request.app.state.settings
    now = s.clock()
    d = p.device
    if not d.sharing_enabled:
        raise HTTPException(409, "El uso compartido está desactivado en este dispositivo")
    recorded = body.recorded_at or now
    if recorded > now + timedelta(minutes=5):
        raise HTTPException(422, "La marca de tiempo está en el futuro")
    if recorded < now - timedelta(hours=24):
        raise HTTPException(422, "La marca de tiempo tiene más de 24 horas")
    last = db.scalar(select(Location).where(Location.device_id == d.id).order_by(Location.received_at.desc()).limit(1))
    if last and (now - last.received_at).total_seconds() < s.min_post_interval_s:
        raise HTTPException(429, "Envíos demasiado frecuentes")
    previous_time = db.scalar(select(Location.recorded_at).where(Location.device_id == d.id)
                              .order_by(Location.recorded_at.desc()).limit(1))
    loc = Location(device_id=d.id, lat=body.lat, lon=body.lon, accuracy_m=body.accuracy_m,
                   recorded_at=recorded, received_at=now, source=body.source)
    db.add(loc)
    d.last_seen_at = now
    db.flush()
    alerts = evaluate_geofences(db, d, loc, previous_time, now)
    db.commit()
    return {"id": loc.id, "alerts_created": alerts}


@router.post("/grants/{grant_id}/approve")
def approve(grant_id: int, body: ApproveIn, request: Request, p: Principal = Depends(device_principal),
            db: Session = Depends(db_dep)):
    now = request.app.state.settings.clock()
    g = owner_grant(db, grant_id, p.user.id)
    if g.status != "pending":
        raise HTTPException(409, "La solicitud ya fue resuelta")
    g.status, g.decided_at = "approved", now
    g.expires_at = now + timedelta(days=body.days)
    g.share_history = body.share_history
    audit(db, now, p.user.id, g.watcher.phone, "grant_approved",
          f"{body.days} días, historial={'sí' if body.share_history else 'no'}")
    db.commit()
    return _grant_row(g, g.watcher)


@router.post("/grants/{grant_id}/deny")
def deny(grant_id: int, request: Request, p: Principal = Depends(device_principal), db: Session = Depends(db_dep)):
    now = request.app.state.settings.clock()
    g = owner_grant(db, grant_id, p.user.id)
    if g.status != "pending":
        raise HTTPException(409, "La solicitud ya fue resuelta")
    g.status, g.decided_at = "denied", now
    audit(db, now, p.user.id, g.watcher.phone, "grant_denied")
    db.commit()
    return _grant_row(g, g.watcher)


@router.post("/grants/{grant_id}/revoke")
def revoke(grant_id: int, request: Request, p: Principal = Depends(device_principal), db: Session = Depends(db_dep)):
    """El dueño retira el consentimiento; el acceso termina de inmediato."""
    now = request.app.state.settings.clock()
    g = owner_grant(db, grant_id, p.user.id)
    if g.status != "approved":
        raise HTTPException(409, "Solo se puede revocar un consentimiento aprobado")
    g.status, g.decided_at = "revoked", now
    audit(db, now, p.user.id, g.watcher.phone, "grant_revoked")
    db.commit()
    return _grant_row(g, g.watcher)


@router.delete("/geofences/{zone_id}", status_code=204)
def delete_zone(zone_id: int, p: Principal = Depends(device_principal), db: Session = Depends(db_dep)):
    zone = db.get(Geofence, zone_id)
    if zone is None or db.get(Grant, zone.grant_id).owner_id != p.user.id:
        raise HTTPException(404, "Zona no encontrada")
    db.delete(zone)
    db.commit()


@router.get("/audit")
def get_audit(p: Principal = Depends(device_principal), db: Session = Depends(db_dep)):
    rows = db.scalars(select(AuditLog).where(AuditLog.subject_id == p.user.id).order_by(AuditLog.id.desc()).limit(50))
    return [{"at": iso(r.at), "who": r.actor_phone, "action": r.action, "detail": r.detail} for r in rows]


@router.delete("/locations", status_code=204)
def delete_my_locations(p: Principal = Depends(device_principal), db: Session = Depends(db_dep)):
    ids = [d.id for d in db.scalars(select(Device).where(Device.user_id == p.user.id))]
    db.execute(delete(Location).where(Location.device_id.in_(ids)))
    db.commit()
