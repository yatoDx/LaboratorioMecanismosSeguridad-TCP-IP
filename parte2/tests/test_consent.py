"""El núcleo ético del sistema: sin consentimiento vigente no hay ubicación."""
from .conftest import OWNER, STRANGER, WATCHER, Env


def _grants(env, h):
    return env.client.get("/api/viewer/grants", headers=h).json()


def test_no_access_before_owner_approves(parties):
    env, owner, watcher = parties
    env.client.put("/api/device/sharing", json={"enabled": True}, headers=owner)
    env.post_loc(owner, 4.6097, -74.0817)
    assert env.client.post("/api/viewer/requests", json={"phone": OWNER}, headers=watcher).status_code == 202
    gid = _grants(env, watcher)[0]["id"]
    assert _grants(env, watcher)[0]["status"] == "pending"
    for path in ["latest", "history", "stats", "geofences", "alerts"]:
        assert env.client.get(f"/api/viewer/grants/{gid}/{path}", headers=watcher).status_code == 403, path


def test_full_consent_flow_and_location_visible(parties):
    env, owner, watcher = parties
    gid = env.consent(owner, watcher)
    env.client.put("/api/device/sharing", json={"enabled": True, "interval_s": 600}, headers=owner)
    assert env.post_loc(owner, 4.6097, -74.0817, accuracy_m=12).status_code == 201
    r = env.client.get(f"/api/viewer/grants/{gid}/latest", headers=watcher)
    assert r.status_code == 200 and (r.json()["lat"], r.json()["lon"]) == (4.6097, -74.0817)
    assert _grants(env, watcher)[0]["status"] == "approved"


def test_sharing_is_off_by_default_and_owner_can_pause(parties):
    env, owner, watcher = parties
    gid = env.consent(owner, watcher)
    assert env.post_loc(owner, 4.6, -74.0).status_code == 409  # apagado por defecto
    env.client.put("/api/device/sharing", json={"enabled": True}, headers=owner)
    env.post_loc(owner, 4.6, -74.0)
    assert env.client.get(f"/api/viewer/grants/{gid}/latest", headers=watcher).status_code == 200
    env.client.put("/api/device/sharing", json={"enabled": False}, headers=owner)
    assert env.client.get(f"/api/viewer/grants/{gid}/latest", headers=watcher).status_code == 409


def test_unregistered_number_gets_same_response_and_creates_nothing(parties):
    env, owner, watcher = parties
    known = env.client.post("/api/viewer/requests", json={"phone": OWNER}, headers=watcher).json()
    unknown = env.client.post("/api/viewer/requests", json={"phone": STRANGER}, headers=watcher).json()
    assert known == unknown
    assert len(_grants(env, watcher)) == 1  # solo el del número registrado


def test_cannot_request_yourself(parties):
    env, owner, watcher = parties
    assert env.client.post("/api/viewer/requests", json={"phone": WATCHER}, headers=watcher).status_code == 422


def test_revocation_is_immediate(parties):
    env, owner, watcher = parties
    gid = env.consent(owner, watcher)
    env.client.put("/api/device/sharing", json={"enabled": True}, headers=owner)
    env.post_loc(owner, 4.6, -74.0)
    assert env.client.get(f"/api/viewer/grants/{gid}/latest", headers=watcher).status_code == 200
    assert env.client.post(f"/api/device/grants/{gid}/revoke", headers=owner).status_code == 200
    for path in ["latest", "history"]:
        assert env.client.get(f"/api/viewer/grants/{gid}/{path}", headers=watcher).status_code == 403
    assert _grants(env, watcher)[0]["status"] == "revoked"


def test_consent_expires_by_itself():
    env = Env(session_viewer_h=100)  # el token del observador no debe caducar antes que el consentimiento
    owner = env.login(OWNER, "device", "Pixel")
    watcher = env.login(WATCHER, "viewer")
    gid = env.consent(owner, watcher, days=2)
    env.client.put("/api/device/sharing", json={"enabled": True}, headers=owner)
    env.post_loc(owner, 4.6, -74.0)
    env.clock.advance(days=1, hours=23)
    assert env.client.get(f"/api/viewer/grants/{gid}/latest", headers=watcher).status_code == 200
    env.clock.advance(hours=2)
    assert env.client.get(f"/api/viewer/grants/{gid}/latest", headers=watcher).status_code == 403
    assert _grants(env, watcher)[0]["status"] == "expired"


def test_deny_blocks_and_has_cooldown(parties):
    env, owner, watcher = parties
    env.client.post("/api/viewer/requests", json={"phone": OWNER}, headers=watcher)
    gid = env.client.get("/api/device/status", headers=owner).json()["requests"][0]["id"]
    assert env.client.post(f"/api/device/grants/{gid}/deny", headers=owner).status_code == 200
    assert env.client.get(f"/api/viewer/grants/{gid}/latest", headers=watcher).status_code == 403
    env.client.post("/api/viewer/requests", json={"phone": OWNER}, headers=watcher)  # insiste
    assert env.client.get("/api/device/status", headers=owner).json()["requests"] == []
    env.clock.advance(hours=25)
    watcher = env.login(WATCHER, "viewer")  # el token de 12 h venció
    env.client.post("/api/viewer/requests", json={"phone": OWNER}, headers=watcher)
    assert len(env.client.get("/api/device/status", headers=owner).json()["requests"]) == 1


def test_no_duplicate_pending_requests(parties):
    env, owner, watcher = parties
    for _ in range(3):
        env.client.post("/api/viewer/requests", json={"phone": OWNER}, headers=watcher)
    assert len(env.client.get("/api/device/status", headers=owner).json()["requests"]) == 1


def test_daily_request_limit(env):
    watcher = env.login(WATCHER, "viewer")
    for i in range(5):
        owner = env.login(f"+57311000000{i}", "device", f"d{i}")
        assert env.client.post("/api/viewer/requests", json={"phone": f"+57311000000{i}"}, headers=watcher).status_code == 202
    owner = env.login("+573119999999", "device", "x")
    assert env.client.post("/api/viewer/requests", json={"phone": "+573119999999"}, headers=watcher).status_code == 429


def test_third_party_cannot_touch_someone_elses_grant(parties):
    env, owner, watcher = parties
    gid = env.consent(owner, watcher)
    stranger = env.login(STRANGER, "viewer")
    for path in ["latest", "history", "stats", "geofences", "alerts"]:
        assert env.client.get(f"/api/viewer/grants/{gid}/{path}", headers=stranger).status_code == 404, path
    assert env.client.post(f"/api/viewer/grants/{gid}/cancel", headers=stranger).status_code == 404
    other_owner = env.login(STRANGER, "device", "Otro")
    assert env.client.post(f"/api/device/grants/{gid}/revoke", headers=other_owner).status_code == 404
    assert env.client.post(f"/api/device/grants/{gid}/approve", json={}, headers=other_owner).status_code == 404


def test_watcher_cannot_approve_own_request(parties):
    env, owner, watcher = parties
    env.client.post("/api/viewer/requests", json={"phone": OWNER}, headers=watcher)
    gid = _grants(env, watcher)[0]["id"]
    assert env.client.post(f"/api/device/grants/{gid}/approve", json={}, headers=watcher).status_code == 403


def test_cannot_approve_twice_or_revoke_pending(parties):
    env, owner, watcher = parties
    env.client.post("/api/viewer/requests", json={"phone": OWNER}, headers=watcher)
    gid = _grants(env, watcher)[0]["id"]
    assert env.client.post(f"/api/device/grants/{gid}/revoke", headers=owner).status_code == 409
    assert env.client.post(f"/api/device/grants/{gid}/approve", json={"days": 3}, headers=owner).status_code == 200
    assert env.client.post(f"/api/device/grants/{gid}/approve", json={"days": 3}, headers=owner).status_code == 409


def test_approval_duration_is_bounded(parties):
    env, owner, watcher = parties
    env.client.post("/api/viewer/requests", json={"phone": OWNER}, headers=watcher)
    gid = _grants(env, watcher)[0]["id"]
    for days in (0, 91, -1):
        assert env.client.post(f"/api/device/grants/{gid}/approve", json={"days": days}, headers=owner).status_code == 422


def test_watcher_can_cancel_and_owner_is_informed(parties):
    env, owner, watcher = parties
    gid = env.consent(owner, watcher)
    assert env.client.post(f"/api/viewer/grants/{gid}/cancel", headers=watcher).status_code == 200
    actions = [a["action"] for a in env.client.get("/api/device/audit", headers=owner).json()]
    assert "grant_cancelled_by_watcher" in actions


def test_history_requires_explicit_authorization(parties):
    env, owner, watcher = parties
    gid = env.consent(owner, watcher, history=False)
    env.client.put("/api/device/sharing", json={"enabled": True}, headers=owner)
    env.post_loc(owner, 4.6, -74.0)
    assert env.client.get(f"/api/viewer/grants/{gid}/latest", headers=watcher).status_code == 200
    assert env.client.get(f"/api/viewer/grants/{gid}/history", headers=watcher).status_code == 403
    assert env.client.get(f"/api/viewer/grants/{gid}/stats", headers=watcher).status_code == 403


def test_owner_audit_trail_is_transparent_and_not_flooded(parties):
    env, owner, watcher = parties
    gid = env.consent(owner, watcher)
    env.client.put("/api/device/sharing", json={"enabled": True}, headers=owner)
    env.post_loc(owner, 4.6, -74.0)
    for _ in range(6):  # el panel consulta cada pocos segundos
        env.client.get(f"/api/viewer/grants/{gid}/latest", headers=watcher)
    actions = [a["action"] for a in env.client.get("/api/device/audit", headers=owner).json()]
    assert actions.count("location_viewed") == 1
    for expected in ("grant_requested", "grant_approved", "sharing_on"):
        assert expected in actions
    env.clock.advance(minutes=11)
    env.client.get(f"/api/viewer/grants/{gid}/latest", headers=watcher)
    actions = [a["action"] for a in env.client.get("/api/device/audit", headers=owner).json()]
    assert actions.count("location_viewed") == 2


def test_audit_is_only_visible_to_its_subject(parties):
    env, owner, watcher = parties
    env.consent(owner, watcher)
    other = env.login(STRANGER, "device", "Otro")
    assert env.client.get("/api/device/audit", headers=other).json() == []
