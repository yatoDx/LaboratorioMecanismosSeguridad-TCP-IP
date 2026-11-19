"""Retención de datos. Ejecutar a diario (cron o Programador de tareas):

    python -m app.maintenance
"""
from __future__ import annotations

from .config import Settings
from .main import make_engine
from .models import Base
from .services import purge
from sqlalchemy.orm import sessionmaker


def main() -> None:
    s = Settings()
    engine = make_engine(s.database_url)
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as db:
        result = purge(db, s)
    print(f"Retención ({s.retention_days} días): " + ", ".join(f"{k}={v}" for k, v in result.items()))


if __name__ == "__main__":
    main()
