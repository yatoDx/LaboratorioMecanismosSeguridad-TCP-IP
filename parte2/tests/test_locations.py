import json
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select

from app.geo import Geocoder, haversine_m, inside
from app.models import Alert, AuditLog, Grant, Location, User
from app.services import purge

from .conftest import OWNER, WATCHER, Env


def _ready(env, owner, watcher, history=True):
    gid = env.consent(owner, watcher, history=history)
    env.client.put("/api/device/sharing", json={"enabled": True}, headers=owner)
    return gid


# ------------------------------------------------------------ validación
@pytest.mark.parametrize("payload", [
    {"lat": 91, "lon": 0}, {"lat": -90.1, "lon": 0}, {"lat": 0, "lon": 180.5}, {"lat": 0, "lon": -181},
    {"lat": "abc", "lon": 0}, {"lat": 0}, {"lat": 0, "lon": 0, "accuracy_m": -1},
    {"lat": 0, "lon": 0, "source": "gps-oculto"},
])
def test_rejects_invalid_coordinates(parties, payload):
    env, owner, _ = parties
    env.client.put("/api/device/sharing", json={"enabled": True}, headers=owner)
    assert env.client.post("/api/device/locations", json=payload, headers=owner).status_code == 422


def test_rejects_nan_and_infinity(parties):
    env, owner, _ = parties
    env.client.put("/api/device/sharing", json={"enabled": True}, headers=owner)
    for raw in ('{"lat": NaN, "lon": 0}', '{"lat": 0, "lon": Infinity}'):
        r = env.client.post("/api/device/locations", content=raw, headers={**owner, "Content-Type": "application/json"})
        assert r.status_code == 422


def test_rejects_future_and_stale_timestamps(parties):
    env, owner, _ = parties
    env.client.put("/api/device/sharing", json={"enabled": True}, headers=owner)
    now = env.clock.now
    assert env.post_loc(owner, 4.6, -74.0, recorded_at=(now + timedelta(minutes=30)).isoformat()).status_code == 422
    assert env.post_loc(owner, 4.6, -74.0, recorded_at=(now - timedelta(hours=25)).isoformat()).status_code == 422
    assert env.post_loc(owner, 4.6, -74.0, recorded_at=(now - timedelta(hours=2)).isoformat() + "Z").status_code == 201


def test_timezone_offsets_are_normalised_to_utc(parties):
    env, owner, watcher = parties
    gid = _ready(env, owner, watcher)
    env.post_loc(owner, 4.6, -74.0, recorded_at="2026-11-18T08:30:00-05:00")  # = 13:30 UTC
    h = env.client.get(f"/api/viewer/grants/{gid}/history", headers=watcher).json()
    assert h[0]["recorded_at"] == "2026-11-18T13:30:00Z"


def test_post_rate_limit():
    env = Env(min_post_interval_s=5)
    owner = env.login(OWNER, "device", "Pixel")
    env.client.put("/api/device/sharing", json={"enabled": True}, headers=owner)
    assert env.post_loc(owner, 4.6, -74.0).status_code == 201
    assert env.post_loc(owner, 4.6, -74.0).status_code == 429
    env.clock.advance(seconds=6)
    assert env.post_loc(owner, 4.6, -74.0).status_code == 201


def test_sharing_interval_bounds(parties):
    env, owner, _ = parties
    for bad in (0, 59, 86401):
        assert env.client.put("/api/device/sharing", json={"enabled": True, "interval_s": bad}, headers=owner).status_code == 422
    assert env.client.put("/api/device/sharing", json={"enabled": True, "interval_s": 600}, headers=owner).json()["interval_s"] == 600


# ------------------------------------------------------------ historial
def test_history_filters_and_ordering(parties):
    env, owner, watcher = parties
    gid = _ready(env, owner, watcher)
    for i, ts in enumerate(["2026-11-18T10:00:00Z", "2026-11-18T11:00:00Z", "2026-11-18T12:00:00Z", "2026-11-18T13:00:00Z"]):
        env.post_loc(owner, 4.60 + i * 0.01, -74.08, recorded_at=ts)
    base = f"/api/viewer/grants/{gid}/history"
    allp = env.client.get(base, headers=watcher).json()
    assert [p["recorded_at"][11:13] for p in allp] == ["10", "11", "12", "13"]
    part = env.client.get(base, params={"since": "2026-11-18T11:00:00Z", "until": "2026-11-18T12:00:00Z"}, headers=watcher).json()
    assert len(part) == 2
    assert env.client.get(base, params={"limit": 2}, headers=watcher).json().__len__() == 2
    assert env.client.get(base, params={"since": "ayer"}, headers=watcher).status_code == 422
    assert env.client.get(base, params={"limit": 0}, headers=watcher).status_code == 422


def test_stats_distance_and_duration(parties):
    env, owner, watcher = parties
    gid = _ready(env, owner, watcher)
    env.post_loc(owner, 4.0, -74.0, recorded_at="2026-11-18T10:00:00Z")
    env.post_loc(owner, 5.0, -74.0, recorded_at="2026-11-18T11:00:00Z")  # 1° de latitud ≈ 111,2 km
    s = env.client.get(f"/api/viewer/grants/{gid}/stats", headers=watcher).json()
    assert s["points"] == 2 and s["duration_s"] == 3600
    assert abs(s["distance_m"] - 111195) < 200


def test_owner_can_delete_their_history(parties):
    env, owner, watcher = parties
    gid = _ready(env, owner, watcher)
    env.post_loc(owner, 4.6, -74.0)
    assert env.client.delete("/api/device/locations", headers=owner).status_code == 204
    assert env.client.get(f"/api/viewer/grants/{gid}/history", headers=watcher).json() == []


def test_latest_uses_newest_recorded_time(parties):
    env, owner, watcher = parties
    gid = _ready(env, owner, watcher)
    env.post_loc(owner, 1.0, 1.0, recorded_at="2026-11-18T13:00:00Z")
    env.post_loc(owner, 2.0, 2.0, recorded_at="2026-11-18T12:00:00Z")  # llega tarde
    assert env.client.get(f"/api/viewer/grants/{gid}/latest", headers=watcher).json()["lat"] == 1.0


# ------------------------------------------------------------ geofencing
def _zone(env, watcher, gid, lat=4.6097, lon=-74.0817, r=500, name="Casa"):
    return env.client.post(f"/api/viewer/grants/{gid}/geofences", json={"name": name, "lat": lat, "lon": lon, "radius_m": r},
                           headers=watcher)


def test_geofence_enter_and_exit_alerts(parties):
    env, owner, watcher = parties
    gid = _ready(env, owner, watcher)
    assert _zone(env, watcher, gid).status_code == 201
    r = env.post_loc(owner, 4.6097, -74.0817, recorded_at="2026-11-18T10:00:00Z")  # dentro: solo fija estado
    assert r.json()["alerts_created"] == 0
    r = env.post_loc(owner, 4.7000, -74.0817, recorded_at="2026-11-18T10:10:00Z")  # ~9,9 km: sale
    assert r.json()["alerts_created"] == 1
    assert env.post_loc(owner, 4.7001, -74.0817, recorded_at="2026-11-18T10:20:00Z").json()["alerts_created"] == 0
    assert env.post_loc(owner, 4.6100, -74.0817, recorded_at="2026-11-18T10:30:00Z").json()["alerts_created"] == 1
    al = env.client.get(f"/api/viewer/grants/{gid}/alerts", headers=watcher).json()
    assert [a["kind"] for a in al] == ["enter", "exit"] and al[0]["zone"] == "Casa"


def test_out_of_order_reading_does_not_flip_state(parties):
    env, owner, watcher = parties
    gid = _ready(env, owner, watcher)
    _zone(env, watcher, gid)
    env.post_loc(owner, 4.6097, -74.0817, recorded_at="2026-11-18T10:00:00Z")
    env.post_loc(owner, 4.9, -74.0817, recorded_at="2026-11-18T09:00:00Z")  # más vieja, fuera: se ignora
    assert env.client.get(f"/api/viewer/grants/{gid}/alerts", headers=watcher).json() == []


def test_no_alerts_after_revocation(parties):
    env, owner, watcher = parties
    gid = _ready(env, owner, watcher)
    _zone(env, watcher, gid)
    env.post_loc(owner, 4.6097, -74.0817, recorded_at="2026-11-18T10:00:00Z")
    env.client.post(f"/api/device/grants/{gid}/revoke", headers=owner)
    r = env.post_loc(owner, 4.9, -74.0817, recorded_at="2026-11-18T10:10:00Z")
    assert r.json()["alerts_created"] == 0
    with env.app.state.SessionLocal() as db:
        assert db.scalar(select(Alert)) is None


def test_geofence_limits_and_validation(parties):
    env, owner, watcher = parties
    gid = _ready(env, owner, watcher)
    for bad in [dict(r=10), dict(r=60000), dict(lat=95), dict(name="")]:
        assert _zone(env, watcher, gid, **bad).status_code == 422
    for i in range(10):
        assert _zone(env, watcher, gid, name=f"z{i}").status_code == 201
    assert _zone(env, watcher, gid, name="z11").status_code == 409


def test_owner_sees_and_can_remove_zones_set_on_them(parties):
    env, owner, watcher = parties
    gid = _ready(env, owner, watcher)
    zid = _zone(env, watcher, gid).json()["id"]
    zones = env.client.get("/api/device/status", headers=owner).json()["geofences"]
    assert zones[0]["name"] == "Casa" and zones[0]["watcher_phone"] == WATCHER
    assert env.client.delete(f"/api/device/geofences/{zid}", headers=owner).status_code == 204
    assert env.client.get(f"/api/viewer/grants/{gid}/geofences", headers=watcher).json() == []


def test_haversine_and_inside():
    assert haversine_m(4.0, -74.0, 4.0, -74.0) == 0
    assert abs(haversine_m(0, 0, 0, 1) - 111195) < 100
    # Bogotá–Medellín; 238 673 m calculado aparte con la ley esférica de los cosenos
    assert abs(haversine_m(4.711, -74.0721, 6.2442, -75.5812) - 238_673) < 50
    assert inside(4.6097, -74.0817, 4.6097, -74.0817, 20)
    assert not inside(4.7, -74.0817, 4.6097, -74.0817, 500)


# ------------------------------------------------------------ geocodificación
def test_geocoder_is_off_by_default(parties):
    env, owner, watcher = parties
    r = env.client.get("/api/viewer/geocode", params={"lat": 4.6, "lon": -74.0}, headers=watcher)
    assert r.status_code == 200 and r.json()["address"] is None


def test_geocoder_rounds_caches_and_survives_errors(monkeypatch):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(dict(request.url.params))
        if request.url.params["lat"] == "9.0":
            return httpx.Response(500)
        return httpx.Response(200, json={"display_name": "Carrera 7, Bogotá"})

    g = Geocoder("https://nominatim.test", httpx.Client(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr("app.geo.time.sleep", lambda s: None)
    assert g.reverse(4.60971234, -74.08171234) == "Carrera 7, Bogotá"
    assert g.reverse(4.60971299, -74.08171299) == "Carrera 7, Bogotá"  # misma celda: caché
    assert len(calls) == 1 and calls[0]["lat"] == "4.6097" and calls[0]["lon"] == "-74.0817"
    assert g.reverse(9.0, -74.0) is None  # error del servicio: no rompe
    assert not Geocoder("").enabled and Geocoder("").reverse(1, 1) is None


# ------------------------------------------------------------ privacidad y retención
def test_delete_account_removes_all_personal_data(parties):
    env, owner, watcher = parties
    gid = _ready(env, owner, watcher)
    _zone(env, watcher, gid)
    env.post_loc(owner, 4.6, -74.0)
    assert env.client.delete("/api/me", headers=owner).status_code == 204
    assert env.client.get("/api/me", headers=owner).status_code == 401
    with env.app.state.SessionLocal() as db:
        assert db.scalar(select(Location)) is None
        assert db.scalar(select(Grant)) is None
        assert db.scalar(select(User).where(User.phone == OWNER)) is None
        assert db.scalar(select(AuditLog).where(AuditLog.subject_id == 1)) is None
    assert env.client.get(f"/api/viewer/grants/{gid}/latest", headers=watcher).status_code == 404


def test_retention_purges_old_locations(parties):
    env, owner, watcher = parties
    gid = _ready(env, owner, watcher)
    env.post_loc(owner, 4.6, -74.0, recorded_at=(env.clock.now - timedelta(hours=1)).isoformat())
    env.clock.advance(days=31)
    owner = env.login(OWNER, "device", "Pixel")  # el token de 30 días también venció
    watcher = env.login(WATCHER, "viewer")
    env.client.put("/api/device/sharing", json={"enabled": True}, headers=owner)
    env.post_loc(owner, 4.7, -74.0)
    with env.app.state.SessionLocal() as db:
        out = purge(db, env.settings)
        assert out["locations"] == 1
        assert db.scalars(select(Location)).all().__len__() == 1
    assert env.client.get(f"/api/viewer/grants/{gid}/history", headers=watcher).status_code == 403  # consentimiento vencido
