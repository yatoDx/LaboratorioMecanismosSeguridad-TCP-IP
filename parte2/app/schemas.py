from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

Num = dict(allow_inf_nan=False)


class RequestCodeIn(BaseModel):
    phone: str = Field(max_length=30)


class VerifyCodeIn(BaseModel):
    phone: str = Field(max_length=30)
    code: str = Field(pattern=r"^\d{6}$")
    role: Literal["device", "viewer"]
    device_label: Optional[str] = Field(None, min_length=1, max_length=40)


class SharingIn(BaseModel):
    enabled: bool
    interval_s: Optional[int] = Field(None, ge=60, le=86400)


class LocationIn(BaseModel):
    lat: float = Field(ge=-90, le=90, **Num)
    lon: float = Field(ge=-180, le=180, **Num)
    accuracy_m: Optional[float] = Field(None, ge=0, le=100000, **Num)
    recorded_at: Optional[datetime] = None
    source: Literal["periodic", "manual"] = "periodic"

    @field_validator("recorded_at")
    @classmethod
    def to_naive_utc(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None and v.tzinfo is not None:
            v = v.astimezone(timezone.utc).replace(tzinfo=None)
        return v


class ApproveIn(BaseModel):
    days: int = Field(7, ge=1, le=90)
    share_history: bool = False


class WatchRequestIn(BaseModel):
    phone: str = Field(max_length=30)
    message: str = Field("", max_length=140)


class GeofenceIn(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    lat: float = Field(ge=-90, le=90, **Num)
    lon: float = Field(ge=-180, le=180, **Num)
    radius_m: float = Field(ge=20, le=50000, **Num)
