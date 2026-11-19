from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Optional

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuthSession, Device, User
from .security import token_hash


def db_dep(request: Request) -> Iterator[Session]:
    db = request.app.state.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def now_dep(request: Request):
    return request.app.state.settings.clock()


@dataclass
class Principal:
    user: User
    session: AuthSession
    device: Optional[Device]


def _principal(request: Request, authorization: Optional[str], db: Session, kind: Optional[str]) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Falta el token de acceso", headers={"WWW-Authenticate": "Bearer"})
    row = db.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash(authorization[7:].strip())))
    now = request.app.state.settings.clock()
    if row is None or row.revoked_at is not None or row.expires_at <= now:
        raise HTTPException(401, "Token inválido o vencido", headers={"WWW-Authenticate": "Bearer"})
    if kind and row.kind != kind:
        raise HTTPException(403, "Este token no sirve para esta operación")
    user = db.get(User, row.user_id)
    device = db.get(Device, row.device_id) if row.device_id else None
    return Principal(user=user, session=row, device=device)


def device_principal(request: Request, authorization: Optional[str] = Header(None),
                     db: Session = Depends(db_dep)) -> Principal:
    return _principal(request, authorization, db, "device")


def viewer_principal(request: Request, authorization: Optional[str] = Header(None),
                     db: Session = Depends(db_dep)) -> Principal:
    return _principal(request, authorization, db, "viewer")


def any_principal(request: Request, authorization: Optional[str] = Header(None),
                  db: Session = Depends(db_dep)) -> Principal:
    return _principal(request, authorization, db, None)
