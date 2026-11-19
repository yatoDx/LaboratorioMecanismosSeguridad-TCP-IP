from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402

OWNER, WATCHER, STRANGER = "+573001112233", "+573004445566", "+573007778899"


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 18, 14, 0, 0)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw) -> None:
        self.now += timedelta(**kw)


class Env:
    def __init__(self, **overrides) -> None:
        self.clock = Clock()
        kw = dict(database_url="sqlite://", secret="s" * 32, sms_backend="memory", clock=self.clock,
                  min_post_interval_s=0)
        kw.update(overrides)
        self.settings = Settings(**kw)
        self.app = create_app(self.settings)
        self.client = TestClient(self.app)
        self.sms = self.app.state.sms

    def login(self, phone: str, role: str, label: str | None = None) -> dict:
        r = self.client.post("/api/auth/request-code", json={"phone": phone})
        assert r.status_code == 202, r.text
        body = {"phone": phone, "code": self.sms.last_code(phone), "role": role}
        if label:
            body["device_label"] = label
        r = self.client.post("/api/auth/verify", json=body)
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['token']}"}

    def consent(self, owner_h, watcher_h, days=7, history=True) -> int:
        """Flujo completo: el observador pide, el dueño aprueba. Devuelve el id del consentimiento."""
        r = self.client.post("/api/viewer/requests", json={"phone": OWNER, "message": "Soy tu hermano"}, headers=watcher_h)
        assert r.status_code == 202
        pend = self.client.get("/api/device/status", headers=owner_h).json()["requests"]
        gid = pend[0]["id"]
        r = self.client.post(f"/api/device/grants/{gid}/approve", json={"days": days, "share_history": history},
                             headers=owner_h)
        assert r.status_code == 200, r.text
        return gid

    def post_loc(self, headers, lat, lon, **extra):
        return self.client.post("/api/device/locations", json={"lat": lat, "lon": lon, **extra}, headers=headers)


@pytest.fixture
def env() -> Env:
    return Env()


@pytest.fixture
def parties(env):
    owner = env.login(OWNER, "device", "Pixel")
    watcher = env.login(WATCHER, "viewer")
    return env, owner, watcher
