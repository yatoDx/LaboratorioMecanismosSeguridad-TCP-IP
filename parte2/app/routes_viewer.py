"""Panel del observador: solo ve lo que el dueño autorizó, mientras dure."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .deps import Principal, db_dep, viewer_principal
from .models import Alert, Device, Geofence, Grant, Location, User
from .schemas import GeofenceIn, WatchRequestIn
from .security import normalize_phone
from .services import (active_grant, audit, audit_throttled, iso, own_grant_as_watcher, path_distance_m)

router = APIRouter(prefix="/api/viewer", tags=["observador"])
MAX_ZONES_PER_GRANT = 10


def _grant_row(g: Grant, owner: User) -> dict:
    return {"id": g.id, "owner_phone": owner.phone, "status": g.status, "requested_at": iso(g.requested_at),
            "decided_at": iso(g.decided_at), "expires_at": iso(g.expires_at), "share_history": g.share_history}


def _loc(l: Location) -> dict:
    return {"id": l.id, "lat": l.lat, "lon": l.lon, "accuracy_m": l.accuracy_m,
            "recorded_at": iso(l.recorded_at), "source": l.source}


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(422, "Fecha inválida; use ISO 8601, por ejemplo 2026-11-18T14:00:00Z")
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def _owner_devices(db: Session, owner_id: int) -> list[int]:
    return [d.id for d in db.scalars(select(Device).where(Device.user_id == owner_id))]


@router.post("/requests", status_code=202)
def request_access(body: WatchRequestIn, request: Request, p: Principal = Depends(viewer_principal),
                   db: Session = Depends(db_dep)):
    """Pide permiso para ver a otra persona. La respuesta es siempre la misma:
    no revela si el número está registrado."""
    s = request.app.state.settings
    now = s.clock()
    try:
        phone = normalize_phone(body.phone)
    except ValueError as e:
        raise HTTPException(422, str(e))
    if phone == p.user.phone:
        raise HTTPException(422, "No puede solicitarse a sí mismo")
    sent_today = db.scalar(select(func.count()).select_from(Grant).where(
        Grant.watcher_id == p.user.id, Grant.requested_at > now - timedelta(days=1)))
    if sent_today >= s.requests_per_day:
        raise HTTPException(429, "Límite diario de solicitudes alcanzado")
    generic = {"status": "enviada", "note": "Si el número tiene la app instalada, su propietario verá la solicitud."}
    owner = db.scalar(select(User).where(User.phone == phone))
    if owner is None or not _owner_devices(db, owner.id):
        return generic
    open_grant = db.scalar(select(Grant).where(Grant.owner_id == owner.id, Grant.watcher_id == p.user.id,
                                               Grant.status.in_(["pending", "approved"])))
    if open_grant is not None and not (open_grant.status == "approved" and open_grant.expires_at <= now):
        return generic
    last = db.scalar(select(Grant).where(Grant.owner_id == owner.id, Grant.watcher_id == p.user.id,
                                         Grant.status == "denied").order_by(Grant.id.desc()))
    if last is not None and last.decided_at > now - timedelta(hours=s.redeny_cooldown_h):
        return generic  # tras un rechazo no se puede insistir durante un tiempo
    db.add(Grant(owner_id=owner.id, watcher_id=p.user.id, status="pending", requested_at=now,
                 message=body.message.strip()))
    audit(db, now, owner.id, p.user.phone, "grant_requested", body.message.strip()[:100])
    db.commit()
    return generic


@router.get("/grants")
def list_grants(request: Request, p: Principal = Depends(viewer_principal), db: Session = Depends(db_dep)):
    now = request.app.state.settings.clock()
    grants = db.scalars(select(Grant).where(Grant.watcher_id == p.user.id).order_by(Grant.id.desc()).limit(50)).all()
    for g in grants:
        if g.status == "approved" and g.expires_at <= now:
            g.status = "expired"
    db.commit()
    return [_grant_row(g, g.owner) for g in grants]


@router.post("/grants/{grant_id}/cancel")
def cancel(grant_id: int, request: Request, p: Principal = Depends(viewer_principal), db: Session = Depends(db_dep)):
    now = request.app.state.settings.clock()
    g = own_grant_as_watcher(db, grant_id, p.user.id, now)
    if g.status not in ("pending", "approved"):
        raise HTTPException(409, "La solicitud ya no está activa")
    g.status, g.decided_at = "revoked", now
    audit(db, now, g.owner_id, p.user.phone, "grant_cancelled_by_watcher")
    db.commit()
    return _grant_row(g, g.owner)


@router.get("/grants/{grant_id}/latest")
def latest(grant_id: int, request: Request, p: Principal = Depends(viewer_principal), db: Session = Depends(db_dep)):
    now = request.app.state.settings.clock()
    g = active_grant(db, grant_id, p.user.id, now)
    sharing = db.scalars(select(Device.id).where(Device.user_id == g.owner_id, Device.sharing_enabled.is_(True))).all()
    if not sharing:
        raise HTTPException(409, "El propietario tiene pausado el uso compartido")
    loc = db.scalar(select(Location).where(Location.device_id.in_(sharing)).order_by(Location.recorded_at.desc()).limit(1))
    if loc is None:
        raise HTTPException(404, "Aún no hay ubicaciones")
    audit_throttled(db, now, g.owner_id, p.user.phone, "location_viewed")
    db.commit()
    return _loc(loc)


def _history_query(db: Session, g: Grant, since: Optional[str], until: Optional[str], limit: int):
    if not g.share_history:
        raise HTTPException(403, "El propietario no autorizó el historial")
    q = select(Location).where(Location.device_id.in_(_owner_devices(db, g.owner_id)))
    a, b = _parse(since), _parse(until)
    if a:
        q = q.where(Location.recorded_at >= a)
    if b:
        q = q.where(Location.recorded_at <= b)
    return q.order_by(Location.recorded_at.asc()).limit(limit)


@router.get("/grants/{grant_id}/history")
def history(grant_id: int, request: Request, since: Optional[str] = None, until: Optional[str] = None,
            limit: int = Query(500, ge=1, le=5000), p: Principal = Depends(viewer_principal),
            db: Session = Depends(db_dep)):
    now = request.app.state.settings.clock()
    g = active_grant(db, grant_id, p.user.id, now)
    rows = db.scalars(_history_query(db, g, since, until, limit)).all()
    audit_throttled(db, now, g.owner_id, p.user.phone, "history_viewed")
    db.commit()
    return [_loc(r) for r in rows]


@router.get("/grants/{grant_id}/stats")
def stats(grant_id: int, request: Request, since: Optional[str] = None, until: Optional[str] = None,
          p: Principal = Depends(viewer_principal), db: Session = Depends(db_dep)):
    """Recorrido: puntos, distancia acumulada y duración del tramo consultado."""
    now = request.app.state.settings.clock()
    g = active_grant(db, grant_id, p.user.id, now)
    rows = db.scalars(_history_query(db, g, since, until, 5000)).all()
    pts = [(r.lat, r.lon) for r in rows]
    dur = (rows[-1].recorded_at - rows[0].recorded_at).total_seconds() if len(rows) > 1 else 0
    return {"points": len(rows), "distance_m": round(path_distance_m(pts), 1), "duration_s": int(dur),
            "from": iso(rows[0].recorded_at) if rows else None, "to": iso(rows[-1].recorded_at) if rows else None}


@router.get("/grants/{grant_id}/geofences")
def list_zones(grant_id: int, request: Request, p: Principal = Depends(viewer_principal), db: Session = Depends(db_dep)):
    g = active_grant(db, grant_id, p.user.id, request.app.state.settings.clock())
    return [{"id": z.id, "name": z.name, "lat": z.lat, "lon": z.lon, "radius_m": z.radius_m}
            for z in db.scalars(select(Geofence).where(Geofence.grant_id == g.id))]


@router.post("/grants/{grant_id}/geofences", status_code=201)
def add_zone(grant_id: int, body: GeofenceIn, request: Request, p: Principal = Depends(viewer_principal),
             db: Session = Depends(db_dep)):
    now = request.app.state.settings.clock()
    g = active_grant(db, grant_id, p.user.id, now)
    n = db.scalar(select(func.count()).select_from(Geofence).where(Geofence.grant_id == g.id))
    if n >= MAX_ZONES_PER_GRANT:
        raise HTTPException(409, f"Máximo {MAX_ZONES_PER_GRANT} zonas por consentimiento")
    z = Geofence(grant_id=g.id, name=body.name.strip(), lat=body.lat, lon=body.lon, radius_m=body.radius_m,
                 created_at=now)
    db.add(z)
    audit(db, now, g.owner_id, p.user.phone, "geofence_created", z.name)
    db.commit()
    return {"id": z.id, "name": z.name, "lat": z.lat, "lon": z.lon, "radius_m": z.radius_m}


@router.delete("/grants/{grant_id}/geofences/{zone_id}", status_code=204)
def del_zone(grant_id: int, zone_id: int, request: Request, p: Principal = Depends(viewer_principal),
             db: Session = Depends(db_dep)):
    g = active_grant(db, grant_id, p.user.id, request.app.state.settings.clock())
    z = db.get(Geofence, zone_id)
    if z is None or z.grant_id != g.id:
        raise HTTPException(404, "Zona no encontrada")
    db.delete(z)
    db.commit()


@router.get("/grants/{grant_id}/alerts")
def alerts(grant_id: int, request: Request, p: Principal = Depends(viewer_principal), db: Session = Depends(db_dep)):
    g = active_grant(db, grant_id, p.user.id, request.app.state.settings.clock())
    q = (select(Alert, Geofence.name).join(Geofence, Geofence.id == Alert.geofence_id)
         .where(Geofence.grant_id == g.id).order_by(Alert.at.desc()).limit(100))
    return [{"id": a.id, "zone": name, "kind": a.kind, "at": iso(a.at), "lat": a.lat, "lon": a.lon}
            for a, name in db.execute(q)]


@router.get("/geocode")
def geocode(request: Request, lat: float = Query(ge=-90, le=90), lon: float = Query(ge=-180, le=180),
            p: Principal = Depends(viewer_principal)):
    """Coordenadas → dirección. Desactivado si no se configuró un geocodificador."""
    g = request.app.state.geocoder
    if not g.enabled:
        return {"address": None, "note": "Geocodificación inversa desactivada (no se envían coordenadas a terceros)."}
    return {"address": g.reverse(lat, lon)}
