"""Registro por número telefónico: código por SMS → token de acceso."""
from __future__ import annotations

import time
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .deps import Principal, any_principal, db_dep
from .models import AuthSession, Device, PhoneCode, User
from .schemas import RequestCodeIn, VerifyCodeIn
from .security import code_hmac, new_code, new_token, normalize_phone, token_hash
from .services import delete_user, iso

router = APIRouter(prefix="/api", tags=["autenticación"])

IP_LIMIT, IP_WINDOW_S = 20, 3600


def _ip_limited(request: Request) -> bool:
    """Límite por IP (en memoria, por proceso) además del límite por número."""
    ip = request.client.host if request.client else "?"
    q = request.app.state.ip_hits[ip]
    now = time.monotonic()
    while q and now - q[0] > IP_WINDOW_S:
        q.popleft()
    if len(q) >= IP_LIMIT:
        return True
    q.append(now)
    return False


@router.post("/auth/request-code", status_code=202)
def request_code(body: RequestCodeIn, request: Request, db: Session = Depends(db_dep)):
    s = request.app.state.settings
    try:
        phone = normalize_phone(body.phone)
    except ValueError as e:
        raise HTTPException(422, str(e))
    if _ip_limited(request):
        raise HTTPException(429, "Demasiadas solicitudes desde esta dirección")
    now = s.clock()
    recent = db.scalar(select(func.count()).select_from(PhoneCode).where(
        PhoneCode.phone == phone, PhoneCode.created_at > now - timedelta(seconds=s.code_window_s)))
    if recent >= s.code_max_per_window:
        raise HTTPException(429, "Demasiados códigos solicitados para este número; espere unos minutos")
    code = new_code()
    db.add(PhoneCode(phone=phone, code_hmac=code_hmac(s.secret, phone, code), created_at=now,
                     expires_at=now + timedelta(seconds=s.code_ttl_s)))
    db.commit()
    request.app.state.sms.send(phone, f"Su código de verificación es {code}. Vence en {s.code_ttl_s // 60} minutos.")
    out = {"sent": True, "expires_in_s": s.code_ttl_s}
    if s.dev_show_code:  # solo demostración
        out["dev_code"] = code
    return out


@router.post("/auth/verify")
def verify(body: VerifyCodeIn, request: Request, db: Session = Depends(db_dep)):
    s = request.app.state.settings
    try:
        phone = normalize_phone(body.phone)
    except ValueError as e:
        raise HTTPException(422, str(e))
    now = s.clock()
    row = db.scalar(select(PhoneCode).where(PhoneCode.phone == phone, PhoneCode.consumed.is_(False),
                                            PhoneCode.expires_at > now).order_by(PhoneCode.id.desc()))
    if row is None:
        raise HTTPException(400, "Código inválido o vencido")
    row.attempts += 1
    if row.attempts > s.code_max_attempts:
        row.consumed = True
        db.commit()
        raise HTTPException(429, "Demasiados intentos; solicite un código nuevo")
    import hmac
    if not hmac.compare_digest(row.code_hmac, code_hmac(s.secret, phone, body.code)):
        db.commit()  # conserva el intento fallido
        raise HTTPException(400, "Código inválido o vencido")
    row.consumed = True

    user = db.scalar(select(User).where(User.phone == phone))
    if user is None:
        user = User(phone=phone, created_at=now)
        db.add(user)
        db.flush()

    device = None
    if body.role == "device":
        label = (body.device_label or "Mi teléfono").strip()
        device = db.scalar(select(Device).where(Device.user_id == user.id, Device.label == label))
        if device is None:
            device = Device(user_id=user.id, label=label, created_at=now)
            db.add(device)
            db.flush()
        for old in db.scalars(select(AuthSession).where(AuthSession.device_id == device.id,
                                                        AuthSession.revoked_at.is_(None))):
            old.revoked_at = now  # una sola sesión activa por dispositivo
        ttl = timedelta(hours=s.session_device_h)
    else:
        ttl = timedelta(hours=s.session_viewer_h)

    token = new_token()
    db.add(AuthSession(token_hash=token_hash(token), user_id=user.id, kind=body.role,
                       device_id=device.id if device else None, created_at=now, expires_at=now + ttl))
    db.commit()
    return {"token": token, "expires_at": iso(now + ttl), "user_id": user.id, "role": body.role,
            "device_id": device.id if device else None}


@router.post("/auth/logout", status_code=204)
def logout(request: Request, p: Principal = Depends(any_principal), db: Session = Depends(db_dep)):
    p.session.revoked_at = request.app.state.settings.clock()
    db.commit()


@router.get("/me")
def me(p: Principal = Depends(any_principal)):
    return {"phone": p.user.phone, "role": p.session.kind, "device_id": p.device.id if p.device else None}


@router.delete("/me", status_code=204)
def delete_me(p: Principal = Depends(any_principal), db: Session = Depends(db_dep)):
    """Supresión de la cuenta y de todos sus datos (ubicaciones, consentimientos, sesiones)."""
    delete_user(db, p.user)
