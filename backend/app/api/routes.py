import json
from pathlib import Path
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.session import get_db
from app.models import (
    ActivityLog, Dependency, DependencyRelationship, Finding, FindingAssignment, FindingEvent,
    FindingObservation, ScanChange, ScanResult, ScanSession, Service, VulnerabilityAdvisory,
    WebhookDelivery,
)
from app.schemas.schemas import (
    AssignmentUpdate, DueDateUpdate, FeedImportRead, FindingRead, NoteUpdate, ScanRead,
    ServiceCreate, ServiceRead, ServiceUpdate, StatusUpdate,
)
from app.services.risk_engine.scoring import assess_risk, default_due_date, finding_priority
from app.services.scanner.runner import dependency_chain, scan_all, scan_service
from app.services.registry import infer_ecosystem
from app.services.vulnerability.importer import import_feed
from app.services.remediation.recommendations import recommendation_for
from app.services.webhooks.delivery import deliver_webhook, receiver_check


router = APIRouter()


def _service_risk(db: Session, service: Service) -> str:
    priorities = db.scalars(select(Finding.priority).where(
        Finding.service_id == service.id, Finding.status != "resolved",
    )).all()
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
    db.add(ActivityLog(entity_type="service", entity_id=service.name, event_type="service.registered",
                       service_id=service.id, details_json=json.dumps({"source": "api"})))
    db.commit()
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
        computed_priority = finding.priority
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
            "risk_score": finding.risk_score,
            "risk_breakdown": json.loads(finding.risk_breakdown_json or "[]"),
            "dev_only": finding.dev_only,
            "status": finding.status,
            "withdrawn": bool(advisory.withdrawn),
            "owner": finding.assigned_owner,
            "due_date": finding.due_date,
            "upgrade_complexity": finding.upgrade_complexity,
            "fixed_version": finding.fixed_version,
        })
    allowed = {"priority", "severity", "service_name", "package_name", "installed_version", "advisory_id", "status"}
    if sort not in allowed:
        raise HTTPException(400, f"Unsupported sort field: {sort}")
    reverse = direction.lower() != "asc"
    sort_key = {"severity": "display_severity"}.get(sort, sort)
    findings.sort(key=lambda item: (item[sort_key] is None, str(item[sort_key]).casefold()), reverse=reverse)
    return findings


def _finding_context(db: Session, finding_id: int):
    row = db.execute(
        select(Finding, Service, Dependency, VulnerabilityAdvisory)
        .join(Service, Service.id == Finding.service_id)
        .join(Dependency, Dependency.id == Finding.dependency_id)
        .join(VulnerabilityAdvisory, VulnerabilityAdvisory.id == Finding.advisory_id)
        .where(Finding.id == finding_id)
    ).first()
    if not row:
        raise HTTPException(404, "Finding not found")
    return row


def _history_event(db: Session, finding: Finding, event_type: str, actor: str,
                   before: dict | None = None, after: dict | None = None,
                   note: str | None = None, scan_id: int | None = None,
                   service: Service | None = None):
    db.add(FindingEvent(
        finding_id=finding.id, event_type=event_type, actor=actor,
        before_json=json.dumps(before) if before is not None else None,
        after_json=json.dumps(after) if after is not None else None,
        note=note, scan_id=scan_id,
    ))
    db.add(ActivityLog(
        entity_type="finding", entity_id=str(finding.id), event_type=f"finding.{event_type}",
        service_id=service.id if service else finding.service_id,
        dependency_id=finding.dependency_id, finding_id=finding.id,
        details_json=json.dumps({"before": before, "after": after, "note": note, "scan_id": scan_id}),
    ))


@router.get("/findings/{finding_id:int}")
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding, service, dependency, advisory = _finding_context(db, finding_id)
    result = db.get(ScanResult, finding.current_scan_result_id)
    recommendation = recommendation_for(db, finding, service, dependency, advisory)
    return {
        "id": finding.id, "service": service.name, "package": dependency.display_name,
        "installed_version": finding.installed_version, "advisory_id": advisory.id,
        "severity": advisory.source_severity, "priority": finding.priority,
        "risk_score": finding.risk_score,
        "risk_breakdown": json.loads(finding.risk_breakdown_json or "[]"),
        "status": finding.status.title(), "owner": finding.assigned_owner,
        "due_date": finding.due_date, "remediation_notes": finding.remediation_notes,
        "created_at": finding.first_seen_at, "updated_at": finding.updated_at,
        "resolution_info": finding.resolution_info,
        "verification_scan_id": finding.verification_scan_id,
        "dependency_type": "Direct" if result and result.direct else "Transitive",
        "recommendation": recommendation,
    }


@router.patch("/findings/{finding_id:int}/assignment")
def assign_finding(finding_id: int, payload: AssignmentUpdate, db: Session = Depends(get_db)):
    finding, service, _dependency, _advisory = _finding_context(db, finding_id)
    before = {"owner": finding.assigned_owner, "due_date": finding.due_date.isoformat() if finding.due_date else None}
    finding.assigned_owner = payload.owner
    finding.due_date = payload.due_date if payload.due_date is not None else finding.due_date
    db.add(FindingAssignment(finding_id=finding.id, owner=payload.owner, due_date=finding.due_date, note=payload.note))
    after = {"owner": finding.assigned_owner, "due_date": finding.due_date.isoformat() if finding.due_date else None}
    _history_event(db, finding, "assigned", payload.actor, before, after, payload.note, service=service)
    db.commit()
    return {"id": finding.id, **after}


@router.patch("/findings/{finding_id:int}/due-date")
def set_due_date(finding_id: int, payload: DueDateUpdate, db: Session = Depends(get_db)):
    finding, service, _dependency, _advisory = _finding_context(db, finding_id)
    before = {"due_date": finding.due_date.isoformat() if finding.due_date else None}
    finding.due_date = payload.due_date
    after = {"due_date": finding.due_date.isoformat() if finding.due_date else None}
    db.add(FindingAssignment(finding_id=finding.id, owner=finding.assigned_owner,
                             due_date=finding.due_date, note=payload.note))
    _history_event(db, finding, "due_date_changed", payload.actor, before, after, payload.note, service=service)
    db.commit()
    return {"id": finding.id, **after}


@router.post("/findings/{finding_id:int}/notes")
def add_finding_note(finding_id: int, payload: NoteUpdate, db: Session = Depends(get_db)):
    finding, service, _dependency, _advisory = _finding_context(db, finding_id)
    finding.remediation_notes = (finding.remediation_notes + "\n" + payload.note).strip()
    _history_event(db, finding, "note_added", payload.actor, note=payload.note, service=service)
    db.commit()
    return {"id": finding.id, "remediation_notes": finding.remediation_notes}


@router.patch("/findings/{finding_id:int}/status")
def change_finding_status(finding_id: int, payload: StatusUpdate, db: Session = Depends(get_db)):
    finding, service, dependency, advisory = _finding_context(db, finding_id)
    requested = payload.status.strip().lower().replace(" ", "_").replace("-", "_")
    if requested not in {"open", "in_progress", "resolved"}:
        raise HTTPException(422, "Status must be Open, In Progress, or Resolved")
    if requested == "resolved":
        try:
            verification = scan_service(db, service)
        except Exception as exc:
            raise HTTPException(500, f"Verification scan failed: {exc}") from exc
        finding = db.get(Finding, finding_id)
        if finding and finding.status == "resolved" and finding.verification_scan_id == verification.id:
            db.refresh(finding)
            return {"id": finding.id, "status": "Resolved", "verification_scan_id": verification.id,
                    "resolution_info": finding.resolution_info}
        if finding and finding.status != "resolved":
            raise HTTPException(409, f"Finding remains vulnerable after verification scan {verification.id}; package {dependency.display_name} {finding.installed_version} is still affected.")
        raise HTTPException(409, "Verification scan could not confirm the finding is resolved.")

    before = {"status": finding.status.title().replace("_", " ")}
    finding.status = requested
    after = {"status": requested.title().replace("_", " ")}
    _history_event(db, finding, "status_changed", payload.actor, before, after, payload.note, service=service)
    db.commit()
    return {"id": finding.id, "status": after["status"]}


@router.get("/findings/{finding_id:int}/history")
def finding_history(finding_id: int, db: Session = Depends(get_db)):
    _finding_context(db, finding_id)
    events = db.scalars(select(FindingEvent).where(FindingEvent.finding_id == finding_id)
                        .order_by(FindingEvent.created_at, FindingEvent.id)).all()
    return [{
        "id": event.id, "event_type": event.event_type, "actor": event.actor,
        "before": json.loads(event.before_json) if event.before_json else None,
        "after": json.loads(event.after_json) if event.after_json else None,
        "note": event.note, "scan_id": event.scan_id, "created_at": event.created_at,
    } for event in events]


@router.get("/findings/overdue")
def overdue_findings(now: datetime | None = None, db: Session = Depends(get_db)):
    now = now or datetime.now(timezone.utc)
    findings = db.scalars(select(Finding).where(
        Finding.status.in_(("open", "in_progress")), Finding.due_date.is_not(None), Finding.due_date < now,
    )).all()
    output = []
    for finding in findings:
        was_notified = db.scalar(select(WebhookDelivery.id).where(
            WebhookDelivery.finding_id == finding.id,
            WebhookDelivery.event_type == "finding.overdue",
        ))
        if not was_notified:
            _finding, service, dependency, advisory = _finding_context(db, finding.id)
            delivery = deliver_webhook(db, "finding.overdue", finding, service, dependency, advisory)
            if delivery:
                _history_event(db, finding, "overdue_notified", "system", after={"delivery_id": delivery.id}, service=service)
        output.append({"finding_id": finding.id, "service_id": finding.service_id, "status": finding.status,
                       "owner": finding.assigned_owner, "due_date": finding.due_date})
    db.commit()
    return output


@router.get("/services/{service_id}/changes")
def service_changes(service_id: int, db: Session = Depends(get_db)):
    if not db.get(Service, service_id):
        raise HTTPException(404, "Service not found")
    rows = db.execute(
        select(ScanChange, ScanSession)
        .join(ScanSession, ScanSession.id == ScanChange.scan_session_id)
        .where(ScanSession.service_id == service_id)
        .order_by(ScanChange.created_at, ScanChange.id)
    ).all()
    return [{"id": change.id, "scan_id": scan.id, "change_type": change.change_type,
             "entity_key": change.entity_key,
             "before": json.loads(change.before_json) if change.before_json else None,
             "after": json.loads(change.after_json) if change.after_json else None,
             "finding_id": change.finding_id, "created_at": change.created_at}
            for change, scan in rows]


@router.get("/activity")
def activity_log(event_type: str | None = None, service_id: int | None = None,
                 start: datetime | None = None, end: datetime | None = None,
                 limit: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db)):
    query = select(ActivityLog).order_by(ActivityLog.created_at, ActivityLog.id)
    if event_type:
        query = query.where(ActivityLog.event_type == event_type)
    if service_id is not None:
        query = query.where(ActivityLog.service_id == service_id)
    if start:
        query = query.where(ActivityLog.created_at >= start)
    if end:
        query = query.where(ActivityLog.created_at <= end)
    rows = db.scalars(query.limit(limit)).all()
    return [{"id": row.id, "event_type": row.event_type, "service_id": row.service_id,
             "dependency_id": row.dependency_id, "finding_id": row.finding_id,
             "details": json.loads(row.details_json or "{}"), "created_at": row.created_at} for row in rows]


@router.get("/webhooks/deliveries")
def webhook_deliveries(success: bool | None = None, event_type: str | None = None,
                       db: Session = Depends(get_db)):
    query = select(WebhookDelivery).order_by(WebhookDelivery.created_at, WebhookDelivery.id)
    if success is not None:
        query = query.where(WebhookDelivery.success == success)
    if event_type:
        query = query.where(WebhookDelivery.event_type == event_type)
    return [{"id": row.id, "event_type": row.event_type, "finding_id": row.finding_id,
             "payload": json.loads(row.payload_json), "response_status": row.response_status,
             "response": json.loads(row.response_json) if row.response_json else None,
             "success": row.success, "error": row.error, "created_at": row.created_at}
            for row in db.scalars(query).all()]


@router.get("/webhooks/deliveries/{delivery_id}/check")
def check_webhook_delivery(delivery_id: int, db: Session = Depends(get_db)):
    delivery = db.get(WebhookDelivery, delivery_id)
    if not delivery:
        raise HTTPException(404, "Webhook delivery not found")
    return receiver_check(db, delivery)


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
