from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ServiceBase(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    owner: str = Field(min_length=1, max_length=160)
    tier: int = Field(default=3, ge=1, le=3)
    internet_facing: bool = False
    description: str = ""
    root_path: str | None = None
    ecosystem: str = "unknown"


class ServiceCreate(ServiceBase):
    pass


class ServiceUpdate(BaseModel):
    owner: str | None = None
    tier: int | None = Field(default=None, ge=1, le=3)
    internet_facing: bool | None = None
    description: str | None = None
    root_path: str | None = None
    ecosystem: str | None = None


class ServiceRead(ServiceBase):
    model_config = ConfigDict(from_attributes=True)
    id: int


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    service_id: int
    status: str
    started_at: datetime
    completed_at: datetime | None
    duration_seconds: float | None
    package_count: int
    vulnerable_count: int
    unverified_count: int
    error: str | None


class FeedImportRead(BaseModel):
    feed: int | None = None
    imported: int
    updated: int
    unchanged: int


class FindingRead(BaseModel):
    id: int
    service_id: int
    service_name: str
    advisory_id: str
    summary: str
    package_name: str
    package_path: str
    installed_version: str
    source_severity: str | None
    display_severity: str | None
    priority: str
    dev_only: bool
    status: str
    withdrawn: bool
