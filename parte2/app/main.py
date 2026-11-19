"""Sistema de localización con consentimiento (Taller 2, Parte II).

Ejecutar:  uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

from collections import defaultdict, deque
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from . import routes_auth, routes_device, routes_viewer
from .config import Settings
from .geo import Geocoder
from .models import Base
from .security import ConsoleSms, MemorySms

STATIC = Path(__file__).parent / "static"

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data: https://tile.openstreetmap.org https://*.tile.openstreetmap.org; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def make_engine(url: str):
    kwargs = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kwargs["poolclass"] = StaticPool
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _fk(dbapi_conn, _):  # SQLite ignora las claves foráneas si no se activan
            dbapi_conn.execute("PRAGMA foreign_keys=ON")
    return engine


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(title="Localización con consentimiento", version="1.0",
                  docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
    engine = make_engine(settings.database_url)
    Base.metadata.create_all(engine)
    app.state.settings = settings
    app.state.engine = engine
    app.state.SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    app.state.sms = MemorySms() if settings.sms_backend == "memory" else ConsoleSms()
    app.state.geocoder = Geocoder(settings.geocoder_url)
    app.state.ip_hits = defaultdict(deque)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Sin el campo `input`: un NaN o Infinity enviado por el cliente no se puede
        # serializar y convertiría un error 422 en un 500.
        errors = [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()]
        return JSONResponse({"detail": errors}, status_code=422)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(self), camera=(), microphone=()"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    app.include_router(routes_auth.router)
    app.include_router(routes_device.router)
    app.include_router(routes_viewer.router)
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    return app

