from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def utcnow():
    return datetime.now(timezone.utc)


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    owner: Mapped[str] = mapped_column(String(160))
    tier: Mapped[int] = mapped_column(Integer, default=3)
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[str] = mapped_column(Text, default="")
    root_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    ecosystem: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Dependency(Base):
    __tablename__ = "dependencies"
    __table_args__ = (UniqueConstraint("ecosystem", "normalized_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(16), index=True)
    normalized_name: Mapped[str] = mapped_column(String(240), index=True)
    display_name: Mapped[str] = mapped_column(String(240))


class ScanSession(Base):
    __tablename__ = "scan_sessions"
    __table_args__ = (Index("ix_scan_service_started", "service_id", "started_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(24), default="running", index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    package_count: Mapped[int] = mapped_column(Integer, default=0)
    vulnerable_count: Mapped[int] = mapped_column(Integer, default=0)
    unverified_count: Mapped[int] = mapped_column(Integer, default=0)
    current_file: Mapped[str | None] = mapped_column(String(240), nullable=True)
    progress_percent: Mapped[float] = mapped_column(Float, default=0)
    packages_inspected: Mapped[int] = mapped_column(Integer, default=0)
    vulnerabilities_discovered: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class ScanFile(Base):
    __tablename__ = "scan_files"
    __table_args__ = (UniqueConstraint("scan_session_id", "file_path"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id", ondelete="CASCADE"), index=True)
    file_path: Mapped[str] = mapped_column(String(240))
    status: Mapped[str] = mapped_column(String(24), default="pending")
    packages_found: Mapped[int] = mapped_column(Integer, default=0)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ScanBatch(Base):
    __tablename__ = "scan_batches"

    id: Mapped[int] = mapped_column(primary_key=True)
    status: Mapped[str] = mapped_column(String(24), default="queued", index=True)
    total_services: Mapped[int] = mapped_column(Integer, default=1)
    completed_services: Mapped[int] = mapped_column(Integer, default=0)
    progress_percent: Mapped[float] = mapped_column(Float, default=0)
    current_service: Mapped[str | None] = mapped_column(String(160), nullable=True)
    scan_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class ScanResult(Base):
    __tablename__ = "scan_results"
    __table_args__ = (
        UniqueConstraint("scan_session_id", "instance_key"),
        Index("ix_scan_result_scan_dependency", "scan_session_id", "dependency_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id", ondelete="CASCADE"), index=True)
    dependency_id: Mapped[int] = mapped_column(ForeignKey("dependencies.id"), index=True)
    instance_key: Mapped[str] = mapped_column(Text)
    package_path: Mapped[str] = mapped_column(Text, default="")
    version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    declared_specifier: Mapped[str | None] = mapped_column(Text, nullable=True)
    direct: Mapped[bool] = mapped_column(Boolean, default=False)
    dev_only: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    resolved: Mapped[bool] = mapped_column(Boolean, default=True)
    verification_state: Mapped[str] = mapped_column(String(24), default="verified", index=True)
    manifest_file: Mapped[str] = mapped_column(String(120), default="")


class DependencyRelationship(Base):
    __tablename__ = "dependency_relationships"
    __table_args__ = (UniqueConstraint("scan_session_id", "parent_result_id", "child_result_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id", ondelete="CASCADE"), index=True)
    parent_result_id: Mapped[int | None] = mapped_column(ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=True)
    child_result_id: Mapped[int] = mapped_column(ForeignKey("scan_results.id", ondelete="CASCADE"), index=True)
    direct: Mapped[bool] = mapped_column(Boolean, default=False)


class VulnerabilityAdvisory(Base):
    __tablename__ = "vulnerability_advisories"

    id: Mapped[str] = mapped_column(String(160), primary_key=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    details: Mapped[str] = mapped_column(Text, default="")
    published: Mapped[str | None] = mapped_column(String(64), nullable=True)
    modified: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    withdrawn: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source_severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    raw_json: Mapped[str] = mapped_column(Text)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AdvisoryRevision(Base):
    __tablename__ = "advisory_revisions"
    __table_args__ = (UniqueConstraint("advisory_id", "payload_hash"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("vulnerability_advisories.id", ondelete="CASCADE"), index=True)
    payload_hash: Mapped[str] = mapped_column(String(64))
    raw_json: Mapped[str] = mapped_column(Text)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VulnerabilityAffectedRange(Base):
    __tablename__ = "vulnerability_affected_ranges"
    __table_args__ = (Index("ix_affected_package", "ecosystem", "normalized_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("vulnerability_advisories.id", ondelete="CASCADE"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(16), index=True)
    package_name: Mapped[str] = mapped_column(String(240))
    normalized_name: Mapped[str] = mapped_column(String(240), index=True)
    range_type: Mapped[str] = mapped_column(String(24), default="ECOSYSTEM")
    events_json: Mapped[str] = mapped_column(Text)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("service_id", "instance_key", "advisory_id"),
        Index("ix_finding_status_severity", "status", "priority"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"), index=True)
    dependency_id: Mapped[int] = mapped_column(ForeignKey("dependencies.id"), index=True)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("vulnerability_advisories.id"), index=True)
    instance_key: Mapped[str] = mapped_column(Text)
    first_scan_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id"), index=True)
    last_seen_scan_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id"), index=True)
    current_scan_result_id: Mapped[int] = mapped_column(ForeignKey("scan_results.id"), index=True)
    installed_version: Mapped[str] = mapped_column(String(120))
    dev_only: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    source_severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    priority: Mapped[str] = mapped_column(String(16), default="Low", index=True)
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)
    assigned_owner: Mapped[str | None] = mapped_column(String(160), nullable=True)
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    remediation_notes: Mapped[str] = mapped_column(Text, default="")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_breakdown_json: Mapped[str] = mapped_column(Text, default="[]")
    fixed_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    upgrade_complexity: Mapped[str] = mapped_column(String(24), default="unknown")
    resolution_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resolution_info: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan_sessions.id"), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FindingAssignment(Base):
    __tablename__ = "finding_assignments"
    __table_args__ = (Index("ix_assignment_finding_created", "finding_id", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    owner: Mapped[str | None] = mapped_column(String(160), nullable=True)
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FindingObservation(Base):
    __tablename__ = "finding_observations"
    __table_args__ = (UniqueConstraint("scan_result_id", "advisory_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_result_id: Mapped[int] = mapped_column(ForeignKey("scan_results.id", ondelete="CASCADE"), index=True)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("vulnerability_advisories.id"), index=True)
    state: Mapped[str] = mapped_column(String(24), index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True)


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(32), index=True)
    entity_id: Mapped[str] = mapped_column(String(160), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id"), nullable=True, index=True)
    dependency_id: Mapped[int | None] = mapped_column(ForeignKey("dependencies.id"), nullable=True, index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True, index=True)
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class FindingEvent(Base):
    __tablename__ = "finding_events"
    __table_args__ = (Index("ix_finding_event_created", "finding_id", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(160), default="system")
    before_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    after_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan_sessions.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class ScanChange(Base):
    __tablename__ = "scan_changes"
    __table_args__ = (Index("ix_scan_change_scan_kind", "scan_session_id", "change_type"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id", ondelete="CASCADE"), index=True)
    change_type: Mapped[str] = mapped_column(String(32), index=True)
    entity_key: Mapped[str] = mapped_column(Text)
    before_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    after_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    __table_args__ = (
        UniqueConstraint("dedupe_key"),
        Index("ix_webhook_delivery_created", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    dedupe_key: Mapped[str] = mapped_column(String(240))
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True, index=True)
    payload_json: Mapped[str] = mapped_column(Text)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    receiver_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
