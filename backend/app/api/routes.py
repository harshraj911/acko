import json
from pathlib import Path
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.session import get_db
from app.models import (
    Dependency, DependencyRelationship, Finding, FindingObservation, ScanResult,
    ScanSession, Service, VulnerabilityAdvisory,
)
from app.schemas.schemas import (
    FeedImportRead, FindingRead, ScanRead, ServiceCreate, ServiceRead, ServiceUpdate,
)
from app.services.risk_engine.scoring import finding_priority
from app.services.scanner.runner import dependency_chain, scan_all, scan_service
from app.services.registry import infer_ecosystem
from app.services.vulnerability.importer import import_feed


router = APIRouter()


def _service_risk(db: Session, service: Service) -> str:
    findings = db.execute(
        select(Finding.source_severity, Finding.dev_only)
        .where(Finding.service_id == service.id, Finding.status != "resolved")
    ).all()
    priorities = [finding_priority(severity, service.tier, service.internet_facing, dev) for severity, dev in findings]
    order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    return max(priorities, key=lambda value: order[value]) if priorities else "None"


@router.get("/services", response_model=list[ServiceRead])
def list_services(
    search: str | None = None,
    ecosystem: str | None = None,
    risk: str | None = None,
    db: Session = Depends(get_db),
):
    services = db.scalars(select(Service).order_by(Service.name)).all()
    if search:
        needle = search.casefold()
        services = [s for s in services if needle in " ".join((s.name, s.owner, s.description)).casefold()]
    if ecosystem:
        services = [s for s in services if s.ecosystem.casefold() == ecosystem.casefold()]
    if risk:
        services = [s for s in services if _service_risk(db, s).casefold() == risk.casefold()]
    return services


@router.get("/services/{service_id}", response_model=ServiceRead)
def get_service(service_id: int, db: Session = Depends(get_db)):
    service = db.get(Service, service_id)
    if not service:
        raise HTTPException(404, "Service not found")
    return service


@router.post("/services", response_model=ServiceRead, status_code=201)
def create_service(payload: ServiceCreate, db: Session = Depends(get_db)):
    if db.scalar(select(Service).where(Service.name == payload.name)):
        raise HTTPException(409, "Service already exists")
    service = Service(**payload.model_dump())
    if service.root_path:
        service.ecosystem = infer_ecosystem(Path(service.root_path))
    db.add(service)
    db.commit()
    db.refresh(service)
    return service


@router.patch("/services/{service_id}", response_model=ServiceRead)
def update_service(service_id: int, payload: ServiceUpdate, db: Session = Depends(get_db)):
    service = db.get(Service, service_id)
    if not service:
        raise HTTPException(404, "Service not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(service, key, value)
    if "root_path" in payload.model_fields_set and service.root_path:
        service.ecosystem = infer_ecosystem(Path(service.root_path))
    db.commit()
    db.refresh(service)
    return service


@router.post("/scans", response_model=list[ScanRead])
def scan_every_service(db: Session = Depends(get_db)):
    try:
        return scan_all(db)
    except Exception as exc:
        raise HTTPException(500, str(exc)) from exc


@router.post("/services/{service_id}/scan", response_model=ScanRead)
def scan_one_service(service_id: int, db: Session = Depends(get_db)):
    service = db.get(Service, service_id)
    if not service:
        raise HTTPException(404, "Service not found")
    try:
        return scan_service(db, service)
    except Exception as exc:
        raise HTTPException(500, str(exc)) from exc


@router.get("/scans", response_model=list[ScanRead])
def list_scans(service_id: int | None = None, db: Session = Depends(get_db)):
    query = select(ScanSession).order_by(ScanSession.started_at.desc(), ScanSession.id.desc())
    if service_id is not None:
        query = query.where(ScanSession.service_id == service_id)
    return db.scalars(query).all()


@router.get("/services/{service_id}/dependencies")
def list_dependencies(service_id: int, scan_id: int | None = None, db: Session = Depends(get_db)):
    service = db.get(Service, service_id)
    if not service:
        raise HTTPException(404, "Service not found")
    if scan_id is None:
        scan = db.scalar(select(ScanSession).where(
            ScanSession.service_id == service_id,
            ScanSession.status == "completed",
        ).order_by(ScanSession.id.desc()))
        if not scan:
            return []
        scan_id = scan.id
    else:
        scan = db.get(ScanSession, scan_id)
        if not scan or scan.service_id != service_id:
            raise HTTPException(404, "Scan not found for service")
    rows = db.execute(
        select(ScanResult, Dependency)
        .join(Dependency, Dependency.id == ScanResult.dependency_id)
        .where(ScanResult.scan_session_id == scan_id)
        .order_by(Dependency.normalized_name, ScanResult.package_path)
    ).all()
    output = []
    for result, dependency in rows:
        output.append({
            "name": dependency.display_name,
            "ecosystem": dependency.ecosystem,
            "version": result.version,
            "specifier": result.declared_specifier,
            "resolved": result.resolved,
            "direct": result.direct,
            "transitive": not result.direct,
            "dev_only": result.dev_only,
            "package_path": result.package_path,
            "manifest_file": result.manifest_file,
            "chain": dependency_chain(db, scan_id, result),
        })
    return output


@router.post("/feed/import", response_model=FeedImportRead)
def feed_import(db: Session = Depends(get_db)):
    try:
        return import_feed(db)
    except Exception as exc:
        raise HTTPException(502, f"Feed import failed: {exc}") from exc


@router.get("/findings", response_model=list[FindingRead])
def list_findings(
    search: str | None = None,
    service_id: int | None = None,
    severity: str | None = None,
    priority: str | None = None,
    status: str | None = None,
    dev_only: bool | None = None,
    withdrawn: bool | None = None,
    sort: str = "priority",
    direction: str = "desc",
    db: Session = Depends(get_db),
):
    rows = db.execute(
        select(Finding, Service, Dependency, VulnerabilityAdvisory)
        .join(Service, Service.id == Finding.service_id)
        .join(Dependency, Dependency.id == Finding.dependency_id)
        .join(VulnerabilityAdvisory, VulnerabilityAdvisory.id == Finding.advisory_id)
    ).all()
    findings = []
    for finding, service, dependency, advisory in rows:
        if service_id is not None and finding.service_id != service_id:
            continue
        if severity and (finding.source_severity or "").casefold() != severity.casefold():
            continue
        if status and finding.status.casefold() != status.casefold():
            continue
        if dev_only is not None and finding.dev_only != dev_only:
            continue
        if withdrawn is not None and bool(advisory.withdrawn) != withdrawn:
            continue
        computed_priority = finding_priority(finding.source_severity, service.tier, service.internet_facing, finding.dev_only)
        if priority and computed_priority.casefold() != priority.casefold():
            continue
        if search and search.casefold() not in " ".join((advisory.id, advisory.summary, dependency.display_name, service.name)).casefold():
            continue
        display_severity = "Medium" if (finding.source_severity or "").upper() == "MODERATE" else finding.source_severity
        findings.append({
            "id": finding.id,
            "service_id": service.id,
            "service_name": service.name,
            "advisory_id": advisory.id,
            "summary": advisory.summary,
            "package_name": dependency.display_name,
            "package_path": finding.instance_key,
            "installed_version": finding.installed_version,
            "source_severity": finding.source_severity,
            "display_severity": display_severity,
            "priority": computed_priority,
            "dev_only": finding.dev_only,
            "status": finding.status,
            "withdrawn": bool(advisory.withdrawn),
        })
    allowed = {"priority", "severity", "service_name", "package_name", "installed_version", "advisory_id", "status"}
    if sort not in allowed:
        raise HTTPException(400, f"Unsupported sort field: {sort}")
    reverse = direction.lower() != "asc"
    sort_key = {"severity": "display_severity"}.get(sort, sort)
    findings.sort(key=lambda item: (item[sort_key] is None, str(item[sort_key]).casefold()), reverse=reverse)
    return findings


@router.get("/findings/unverified")
def list_unverified(db: Session = Depends(get_db)):
    rows = db.execute(
        select(ScanResult, Dependency, ScanSession)
        .join(Dependency, Dependency.id == ScanResult.dependency_id)
        .join(ScanSession, ScanSession.id == ScanResult.scan_session_id)
        .where(ScanResult.verification_state == "unverified")
        .order_by(ScanSession.id.desc(), ScanResult.id)
    ).all()
    output = []
    for result, dependency, scan in rows:
        observations = db.scalars(select(FindingObservation).where(
            FindingObservation.scan_result_id == result.id,
            FindingObservation.state == "unverified",
        )).all()
        advisory_ids = [observation.advisory_id for observation in observations] or [None]
        for advisory_id in advisory_ids:
            advisory = db.get(VulnerabilityAdvisory, advisory_id) if advisory_id else None
            if advisory and advisory.withdrawn:
                continue
            output.append({
                "service_id": scan.service_id,
                "advisory_id": advisory_id,
                "package_name": dependency.display_name,
                "specifier": result.declared_specifier,
                "package_path": result.package_path,
                "dev_only": result.dev_only,
                "state": "unverified",
                "scan_id": scan.id,
            })
    return output
