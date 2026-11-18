from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.api.routes import router
from app.core.config import settings
from app.database.base import Base
from app.database.migrations import migrate_existing_sqlite
from app.database.session import SessionLocal, engine
from app.models import *  # noqa: F403 - imports model metadata before create_all
from app.models import ScanSession
from app.services.overdue import overdue_scheduler
from app.services.registry import register_kit_services
from app.services.scanner.jobs import launch_initial_scan
from app.services.vulnerability.importer import import_feed


@asynccontextmanager
async def lifespan(_app: FastAPI):
    migrate_existing_sqlite(engine)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        register_kit_services(db)
        if settings.auto_initial_scan:
            has_scans = db.scalar(select(ScanSession.id).limit(1)) is not None
            if not has_scans:
                try:
                    import_feed(db)
                except Exception as exc:
                    print(f"Initial feed import note: {exc}")
                try:
                    launch_initial_scan()
                except Exception as exc:
                    print(f"Initial scan launch note: {exc}")
    overdue_scheduler.start()
    yield
    overdue_scheduler.stop()


app = FastAPI(title="Dependency Watch API", version="0.1.0", lifespan=lifespan)

origins = [origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok", "kit_path": str(settings.kit_path)}
