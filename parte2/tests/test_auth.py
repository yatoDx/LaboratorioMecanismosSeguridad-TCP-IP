from sqlalchemy import select

from app.models import AuthSession, PhoneCode
from app.security import normalize_phone

from .conftest import OWNER, STRANGER, WATCHER, Env


def test_normalize_phone():
    assert normalize_phone("+57 300 111-2233") == "+573001112233"
    for bad in ["3001112233", "+0123456789", "+57abc", "", "+1", "+" + "1" * 20]:
        try:
            normalize_phone(bad)
        except ValueError:
            continue
        raise AssertionError(bad)


def test_register_device_and_me(env):
    h = env.login(OWNER, "device", "Pixel")
    r = env.client.get("/api/me", headers=h)
    assert r.json() == {"phone": OWNER, "role": "device", "device_id": 1}


def test_invalid_phone_is_rejected(env):
    r = env.client.post("/api/auth/request-code", json={"phone": "3001112233"})
    assert r.status_code == 422


def test_code_and_token_are_not_stored_in_clear(env):
    r = env.client.post("/api/auth/request-code", json={"phone": OWNER})
    code = env.sms.last_code(OWNER)
    token = env.client.post("/api/auth/verify", json={"phone": OWNER, "code": code, "role": "viewer"}).json()["token"]
    with env.app.state.SessionLocal() as db:
        stored = db.scalar(select(PhoneCode.code_hmac))
        assert code not in stored and len(stored) == 64
        assert token not in db.scalar(select(AuthSession.token_hash))


def test_code_is_not_returned_unless_dev_flag(env):
    r = env.client.post("/api/auth/request-code", json={"phone": OWNER})
    assert "dev_code" not in r.json()
    dev = Env(dev_show_code=True)
    assert len(dev.client.post("/api/auth/request-code", json={"phone": OWNER}).json()["dev_code"]) == 6


def test_wrong_code_then_lockout_even_with_right_code(env):
    env.client.post("/api/auth/request-code", json={"phone": OWNER})
    good = env.sms.last_code(OWNER)
    wrong = "000000" if good != "000000" else "111111"
    for _ in range(5):
        r = env.client.post("/api/auth/verify", json={"phone": OWNER, "code": wrong, "role": "viewer"})
        assert r.status_code == 400
    r = env.client.post("/api/auth/verify", json={"phone": OWNER, "code": good, "role": "viewer"})
    assert r.status_code == 429  # bloqueado: hay que pedir uno nuevo


def test_expired_code(env):
    env.client.post("/api/auth/request-code", json={"phone": OWNER})
    code = env.sms.last_code(OWNER)
    env.clock.advance(seconds=601)
    assert env.client.post("/api/auth/verify", json={"phone": OWNER, "code": code, "role": "viewer"}).status_code == 400


def test_code_is_single_use(env):
    env.client.post("/api/auth/request-code", json={"phone": OWNER})
    code = env.sms.last_code(OWNER)
    body = {"phone": OWNER, "code": code, "role": "viewer"}
    assert env.client.post("/api/auth/verify", json=body).status_code == 200
    assert env.client.post("/api/auth/verify", json=body).status_code == 400


def test_code_request_rate_limit_per_phone(env):
    for _ in range(3):
        assert env.client.post("/api/auth/request-code", json={"phone": OWNER}).status_code == 202
    assert env.client.post("/api/auth/request-code", json={"phone": OWNER}).status_code == 429
    assert env.client.post("/api/auth/request-code", json={"phone": WATCHER}).status_code == 202  # otro número
    env.clock.advance(seconds=601)
    assert env.client.post("/api/auth/request-code", json={"phone": OWNER}).status_code == 202


def test_code_request_rate_limit_per_ip(env):
    codes = [f"+57300{i:07d}" for i in range(25)]
    statuses = [env.client.post("/api/auth/request-code", json={"phone": p}).status_code for p in codes]
    assert statuses[:20] == [202] * 20 and set(statuses[20:]) == {429}


def test_endpoints_require_token(env):
    for method, url in [("get", "/api/me"), ("get", "/api/device/status"), ("post", "/api/device/locations"),
                        ("get", "/api/viewer/grants"), ("get", "/api/device/audit")]:
        assert getattr(env.client, method)(url).status_code == 401, url
    assert env.client.get("/api/me", headers={"Authorization": "Bearer basura"}).status_code == 401


def test_roles_are_separated(parties):
    env, owner, watcher = parties
    assert env.client.get("/api/viewer/grants", headers=owner).status_code == 403
    assert env.client.get("/api/device/status", headers=watcher).status_code == 403
    assert env.post_loc(watcher, 4.6, -74.0).status_code == 403


def test_token_expires_and_logout_revokes(env):
    h = env.login(WATCHER, "viewer")
    assert env.client.get("/api/me", headers=h).status_code == 200
    h2 = env.login(WATCHER, "viewer")
    assert env.client.post("/api/auth/logout", headers=h2).status_code == 204
    assert env.client.get("/api/me", headers=h2).status_code == 401
    env.clock.advance(hours=13)  # viewer: 12 h
    assert env.client.get("/api/me", headers=h).status_code == 401


def test_new_login_of_same_device_revokes_old_session(env):
    old = env.login(OWNER, "device", "Pixel")
    new = env.login(OWNER, "device", "Pixel")
    assert env.client.get("/api/me", headers=old).status_code == 401
    assert env.client.get("/api/me", headers=new).status_code == 200


def test_multiple_devices_per_number(env):
    a = env.login(OWNER, "device", "Pixel")
    b = env.login(OWNER, "device", "Tablet")
    assert env.client.get("/api/me", headers=a).json()["device_id"] != env.client.get("/api/me", headers=b).json()["device_id"]


def test_security_headers_and_index(env):
    r = env.client.get("/")
    assert r.status_code == 200
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert env.client.get("/api/me").headers["cache-control"] == "no-store"
