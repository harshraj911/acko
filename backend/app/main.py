from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import router
from app.core.config import settings
from app.database.base import Base
from app.database.session import SessionLocal, engine
from app.models import *  # noqa: F403 - imports model metadata before create_all
from app.services.registry import register_kit_services


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        register_kit_services(db)
    yield


app = FastAPI(title="Dependency Watch API", version="0.1.0", lifespan=lifespan)
app.include_router(router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok", "kit_path": str(settings.kit_path)}
