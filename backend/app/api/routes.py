import asyncio
import json
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.session import SessionLocal, get_db
from app.models import (
    ActivityLog, Dependency, DependencyRelationship, Finding, FindingAssignment, FindingEvent,
    FindingObservation, ScanChange, ScanResult, ScanSession, Service, VulnerabilityAdvisory,
    ScanBatch, WebhookDelivery,
)
from app.schemas.schemas import (
    AssignmentUpdate, DueDateUpdate, FeedImportRead, FindingRead, NoteUpdate, ScanRead,
    ServiceCreate, ServiceRead, ServiceUpdate, StatusUpdate,
)
from app.services.risk_engine.scoring import DUE_DATE_DAYS, PRIORITY_BANDS, RISK_WEIGHTS
from app.services.scanner.runner import dependency_chain, scan_service
from app.services.registry import infer_ecosystem
from app.services.vulnerability.importer import import_feed
from app.services.remediation.recommendations import recommendation_for
from app.services.webhooks.delivery import deliver_webhook, receiver_check
from app.services.scanner.jobs import create_scan_job, create_single_scan
from app.services.scanner.progress import scan_progress
from app.services.risk_engine.scoring import assess_risk
from app.services.analytics import analytics_data, overview_data


router = APIRouter()


def _service_risk(db: Session, service: Service) -> str:
    priorities = db.scalars(select(Finding.priority).where(
        Finding.service_id == service.id, Finding.status != "resolved",
    )).all()
    order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    return max(priorities, key=lambda value: order[value]) if priorities else "None"


@router.get("/services")
def list_services(
    ecosystem: str | None = None,
    risk: str | None = None,
    search: str | None = None,
    sort: str = "name",
    direction: str = "asc",
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
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
    if sort not in {"name", "owner", "tier", "ecosystem"}:
        raise HTTPException(400, "Unsupported service sort field")
    services.sort(key=lambda service: str(getattr(service, sort)).casefold(), reverse=direction.lower() == "desc")
    return {"items": services[offset:offset + limit], "total": len(services), "limit": limit, "offset": offset}


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


@router.post("/scans", status_code=202)
def scan_every_service(db: Session = Depends(get_db)):
    service_ids = db.scalars(select(Service.id).order_by(Service.name)).all()
    if not service_ids:
        return {"batch_id": None, "scan_session_id": None, "scan_ids": [], "status": "empty"}
    batch, scans = create_scan_job(service_ids)
    return {
        "batch_id": batch.id,
        "scan_session_id": scans[0].id if scans else None,
        "scan_ids": [scan.id for scan in scans],
        "status": batch.status,
    }


@router.post("/services/{service_id}/scan", status_code=202)
def scan_one_service(service_id: int, db: Session = Depends(get_db)):
    service = db.get(Service, service_id)
    if not service:
        raise HTTPException(404, "Service not found")
    scan = create_single_scan(service_id)
    return {
        "scan_id": scan.id,
        "scan_session_id": scan.id,
        "service_id": service_id,
        "status": scan.status,
    }


@router.get("/scans")
def list_scans(service_id: int | None = None, status: str | None = None,
               limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
               db: Session = Depends(get_db)):
    query = select(ScanSession).order_by(ScanSession.started_at.desc(), ScanSession.id.desc())
    total_query = select(func.count()).select_from(ScanSession)
    if service_id is not None:
        query = query.where(ScanSession.service_id == service_id)
        total_query = total_query.where(ScanSession.service_id == service_id)
    if status:
        query = query.where(ScanSession.status == status)
        total_query = total_query.where(ScanSession.status == status)
    items = db.scalars(query.limit(limit).offset(offset)).all()
    return _page(items, db.scalar(total_query) or 0, limit, offset)


@router.get("/services/{service_id}/dependencies")
def list_dependencies(service_id: int, scan_id: int | None = None,
                      search: str | None = None, sort: str = "name", direction: str = "asc",
                      limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                      db: Session = Depends(get_db)):
    service = db.get(Service, service_id)
    if not service:
        raise HTTPException(404, "Service not found")
    if scan_id is None:
        scan = db.scalar(select(ScanSession).where(
            ScanSession.service_id == service_id,
            ScanSession.status == "completed",
        ).order_by(ScanSession.id.desc()))
        if not scan:
            return _page([], 0, limit, offset)
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
    if search:
        output = [item for item in output if search.casefold() in item["name"].casefold()]
    if sort not in {"name", "version", "direct", "dev_only"}:
        raise HTTPException(400, "Unsupported dependency sort field")
    output.sort(key=lambda item: str(item[sort]).casefold(), reverse=direction.lower() == "desc")
    return _page(output, len(output), limit, offset)


@router.post("/feed/import", response_model=FeedImportRead)
def feed_import(db: Session = Depends(get_db)):
    try:
        return import_feed(db)
    except Exception as exc:
        raise HTTPException(502, f"Feed import failed: {exc}") from exc


@router.get("/findings")
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
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
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
    return _page(findings, len(findings), limit, offset)


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
            new_scan = ScanSession(service_id=service.id, status="queued")
            db.add(new_scan)
            db.commit()
            verification = scan_service(db, service, scan_id=new_scan.id)
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
def service_changes(service_id: int, limit: int = Query(100, ge=1, le=500),
                    offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    if not db.get(Service, service_id):
        raise HTTPException(404, "Service not found")
    rows = db.execute(
        select(ScanChange, ScanSession)
        .join(ScanSession, ScanSession.id == ScanChange.scan_session_id)
        .where(ScanSession.service_id == service_id)
        .order_by(ScanChange.created_at, ScanChange.id)
    ).all()
    items = [{"id": change.id, "scan_id": scan.id, "change_type": change.change_type,
             "entity_key": change.entity_key,
             "before": json.loads(change.before_json) if change.before_json else None,
             "after": json.loads(change.after_json) if change.after_json else None,
             "finding_id": change.finding_id, "created_at": change.created_at}
            for change, scan in rows]
    return _page(items, len(items), limit, offset)


@router.get("/activity")
def activity_log(event_type: str | None = None, service_id: int | None = None,
                 start: datetime | None = None, end: datetime | None = None,
                 limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                 db: Session = Depends(get_db)):
    query = select(ActivityLog).order_by(ActivityLog.created_at, ActivityLog.id)
    if event_type:
        query = query.where(ActivityLog.event_type == event_type)
    if service_id is not None:
        query = query.where(ActivityLog.service_id == service_id)
    if start:
        query = query.where(ActivityLog.created_at >= start)
    if end:
        query = query.where(ActivityLog.created_at <= end)
    items_query = query.limit(limit).offset(offset)
    rows = db.scalars(items_query).all()
    items = [{"id": row.id, "event_type": row.event_type, "service_id": row.service_id,
             "dependency_id": row.dependency_id, "finding_id": row.finding_id,
             "details": json.loads(row.details_json or "{}"), "created_at": row.created_at} for row in rows]
    count_query = select(func.count()).select_from(ActivityLog)
    if event_type:
        count_query = count_query.where(ActivityLog.event_type == event_type)
    if service_id is not None:
        count_query = count_query.where(ActivityLog.service_id == service_id)
    if start:
        count_query = count_query.where(ActivityLog.created_at >= start)
    if end:
        count_query = count_query.where(ActivityLog.created_at <= end)
    return _page(items, db.scalar(count_query) or 0, limit, offset)


@router.get("/webhooks/deliveries")
def webhook_deliveries(success: bool | None = None, event_type: str | None = None,
                       limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                       db: Session = Depends(get_db)):
    query = select(WebhookDelivery).order_by(WebhookDelivery.created_at, WebhookDelivery.id)
    if success is not None:
        query = query.where(WebhookDelivery.success == success)
    if event_type:
        query = query.where(WebhookDelivery.event_type == event_type)
    items = [{"id": row.id, "event_type": row.event_type, "finding_id": row.finding_id,
             "payload": json.loads(row.payload_json), "response_status": row.response_status,
             "response": json.loads(row.response_json) if row.response_json else None,
             "success": row.success, "error": row.error, "created_at": row.created_at}
            for row in db.scalars(query).all()]
    return _page(items, len(items), limit, offset)


@router.get("/webhooks/deliveries/{delivery_id}/check")
def check_webhook_delivery(delivery_id: int, db: Session = Depends(get_db)):
    delivery = db.get(WebhookDelivery, delivery_id)
    if not delivery:
        raise HTTPException(404, "Webhook delivery not found")
    return receiver_check(db, delivery)


@router.get("/settings")
def read_settings():
    return {
        "feed_url": settings.feed_url,
        "webhook_url": settings.webhook_url,
        "due_date_rules_days": DUE_DATE_DAYS,
        "risk_weights": RISK_WEIGHTS,
        "priority_bands": [{"minimum_score": score, "priority": name} for score, name in PRIORITY_BANDS],
    }


@router.post("/settings/sync-feed")
@router.post("/feed/sync")
def sync_feed_now(db: Session = Depends(get_db)):
    try:
        return import_feed(db)
    except Exception as exc:
        raise HTTPException(502, f"Feed sync failed: {exc}") from exc


@router.post("/settings/test-webhook")
@router.post("/webhooks/test")
def send_test_webhook(db: Session = Depends(get_db)):
    try:
        response = requests.post(
            f"{settings.webhook_url.rstrip('/')}/api/dependency-watch/test",
            json={"event_type": "dependency-watch.test", "service": None, "package": None,
                  "advisory_id": None, "severity": None, "priority": None,
                  "finding_id": None, "reference": "/settings"},
            timeout=5,
        )
        try:
            body = response.json()
        except ValueError:
            body = {"body": response.text[:1000]}
        return {"success": response.ok and isinstance(body, dict) and body.get("ok") is True,
                "status_code": response.status_code, "response": body}
    except Exception as exc:
        return {"success": False, "status_code": 500, "response": {"error": str(exc)}}


@router.get("/overview")
@router.get("/analytics/overview")
def overview(dev_only: bool | None = None, db: Session = Depends(get_db)):
    return overview_data(db, dev_only)


@router.get("/analytics")
def analytics(dev_only: bool | None = None, db: Session = Depends(get_db)):
    return analytics_data(db, dev_only)


@router.get("/analytics/vulnerabilities-by-severity")
def analytics_vulns_by_severity(dev_only: bool | None = None, db: Session = Depends(get_db)):
    return analytics_data(db, dev_only)["vulnerabilities_by_severity"]


@router.get("/analytics/vulnerabilities-by-service")
def analytics_vulns_by_service(dev_only: bool | None = None, db: Session = Depends(get_db)):
    return analytics_data(db, dev_only)["vulnerabilities_by_service"]


@router.get("/analytics/open-over-time")
def analytics_open_over_time(dev_only: bool | None = None, db: Session = Depends(get_db)):
    return analytics_data(db, dev_only)["open_findings_over_time"]


@router.get("/analytics/resolved-over-time")
def analytics_resolved_over_time(dev_only: bool | None = None, db: Session = Depends(get_db)):
    return analytics_data(db, dev_only)["resolved_findings_over_time"]


@router.get("/analytics/resolution-time")
def analytics_resolution_time(dev_only: bool | None = None, db: Session = Depends(get_db)):
    data = analytics_data(db, dev_only)
    return {"average_resolution_time_seconds": data["average_resolution_time_seconds"]}


@router.get("/analytics/overdue")
def analytics_overdue(dev_only: bool | None = None, db: Session = Depends(get_db)):
    data = analytics_data(db, dev_only)
    return {"overdue_findings": data["overdue_findings"]}


@router.get("/analytics/packages-scanned")
def analytics_packages_scanned(dev_only: bool | None = None, db: Session = Depends(get_db)):
    data = analytics_data(db, dev_only)
    return {"total_packages_scanned": data["total_packages_scanned"]}


@router.get("/analytics/most-vulnerable-services")
def analytics_most_vulnerable_services(dev_only: bool | None = None, db: Session = Depends(get_db)):
    return analytics_data(db, dev_only)["most_vulnerable_services"]


@router.get("/graph")
def global_graph(service_id: int | None = None, db: Session = Depends(get_db)):
    if service_id is not None:
        return service_graph(service_id, None, db)
    services = db.scalars(select(Service).order_by(Service.name)).all()
    all_nodes = []
    all_edges = []
    all_chains = []
    for service in services:
        sub = service_graph(service.id, None, db)
        all_nodes.extend(sub.get("nodes", []))
        all_edges.extend(sub.get("edges", []))
        all_chains.extend(sub.get("vulnerable_chains", []))
    unique_nodes = {node["id"]: node for node in all_nodes}
    return {"nodes": list(unique_nodes.values()), "edges": all_edges, "vulnerable_chains": all_chains}


@router.get("/services/{service_id}/graph")
def service_graph(service_id: int, scan_id: int | None = None, db: Session = Depends(get_db)):
    service = db.get(Service, service_id)
    if not service:
        raise HTTPException(404, "Service not found")
    if scan_id is None:
        latest = db.scalar(select(ScanSession).where(
            ScanSession.service_id == service_id, ScanSession.status == "completed",
        ).order_by(ScanSession.id.desc()))
        if not latest:
            return {"nodes": [], "edges": []}
        scan_id = latest.id
    results = db.execute(select(ScanResult, Dependency).join(
        Dependency, Dependency.id == ScanResult.dependency_id,
    ).where(ScanResult.scan_session_id == scan_id)).all()
    nodes = [{"id": f"dep:{result.id}", "type": "dependency", "label": dependency.display_name,
              "version": result.version, "path": result.package_path, "direct": result.direct,
              "transitive": not result.direct, "dev_only": result.dev_only,
              "resolved": result.resolved, "vulnerable": False}
             for result, dependency in results]
    result_ids = [result.id for result, _ in results]
    vulnerable = {observation.scan_result_id for observation in db.scalars(select(FindingObservation).where(
        FindingObservation.scan_result_id.in_(result_ids or [-1]),
        FindingObservation.state == "vulnerable",
    )).all()}
    for node in nodes:
        result_id = int(node["id"].split(":")[1])
        node["vulnerable"] = result_id in vulnerable
    edges = [{"source": f"service:{service_id}", "target": f"dep:{result.id}", "direct": True}
             for result, _ in results if result.direct]
    for relationship in db.scalars(select(DependencyRelationship).where(
        DependencyRelationship.scan_session_id == scan_id,
    )).all():
        if relationship.parent_result_id:
            edges.append({"source": f"dep:{relationship.parent_result_id}",
                          "target": f"dep:{relationship.child_result_id}", "direct": False})
    chains = []
    for node in nodes:
        if not node["vulnerable"]:
            continue
        current = node["id"]
        chain = [current]
        while True:
            parent_edge = next((edge for edge in edges if edge["target"] == current), None)
            if not parent_edge:
                break
            current = parent_edge["source"]
            chain.append(current)
            if current == f"service:{service_id}":
                break
        chains.append({"target": node["id"], "chain": list(reversed(chain))})
    return {"scan_id": scan_id, "nodes": [{"id": f"service:{service_id}", "type": "service", "label": service.name}, *nodes],
            "edges": edges, "vulnerable_chains": chains}


@router.get("/findings/unverified")
def list_unverified(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                    db: Session = Depends(get_db)):
    latest_scan_ids = db.scalars(
        select(func.max(ScanSession.id))
        .where(ScanSession.status == "completed")
        .group_by(ScanSession.service_id)
    ).all()
    if not latest_scan_ids:
        return _page([], 0, limit, offset)

    rows = db.execute(
        select(ScanResult, Dependency, ScanSession)
        .join(Dependency, Dependency.id == ScanResult.dependency_id)
        .join(ScanSession, ScanSession.id == ScanResult.scan_session_id)
        .where(
            ScanResult.scan_session_id.in_(latest_scan_ids),
            ScanResult.verification_state == "unverified",
        )
        .order_by(ScanSession.service_id, Dependency.normalized_name)
    ).all()
    output = []
    seen = set()
    for result, dependency, scan in rows:
        observations = db.scalars(select(FindingObservation).where(
            FindingObservation.scan_result_id == result.id,
            FindingObservation.state == "unverified",
        )).all()
        advisory_ids = [observation.advisory_id for observation in observations] or [None]
        for advisory_id in advisory_ids:
            if advisory_id:
                advisory = db.get(VulnerabilityAdvisory, advisory_id)
                if advisory and advisory.withdrawn:
                    continue
            dedupe_key = (scan.service_id, dependency.normalized_name, advisory_id)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
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
    return _page(output, len(output), limit, offset)


def _page(items: list[Any], total: int, limit: int, offset: int):
    return {"items": items[offset:offset + limit], "total": total, "limit": limit, "offset": offset}


def _scan_progress_payload(scan_id: int):
    with SessionLocal() as db:
        scan = db.get(ScanSession, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        service = db.get(Service, scan.service_id)
        duration = scan.duration_seconds
        if scan.status in {"queued", "running"}:
            started = scan.started_at
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            duration = (datetime.now(timezone.utc) - started).total_seconds() if scan.status == "running" else 0
        return {
            "scan_id": scan.id,
            "scan_session_id": scan.id,
            "batch_id": None,
            "service_id": scan.service_id,
            "current_service": service.name if service else None,
            "current_file": scan.current_file,
            "file_being_processed": scan.current_file,
            "packages_inspected": scan.packages_inspected,
            "vulnerabilities_discovered": scan.vulnerabilities_discovered,
            "progress_percent": scan.progress_percent,
            "overall_progress": scan.progress_percent,
            "elapsed_seconds": duration,
            "elapsed_duration": duration,
            "status": scan.status,
            "error": scan.error,
        }


@router.get("/scans/{scan_id}/progress")
def scan_progress_poll(scan_id: int):
    return _scan_progress_payload(scan_id)


@router.get("/scans/{scan_id}/events")
@router.get("/scans/{scan_id}/progress/stream")
async def scan_progress_events(scan_id: int):
    _scan_progress_payload(scan_id)

    async def generate():
        sequence = 0
        terminal = {"completed", "failed"}
        while True:
            events = scan_progress.after(scan_id, sequence)
            for event in events:
                sequence = event["sequence"]
                yield f"id: {sequence}\nevent: progress\ndata: {json.dumps(event)}\n\n"
                if event.get("status") in terminal:
                    return
            current = _scan_progress_payload(scan_id)
            if current["status"] in terminal:
                yield f"event: progress\ndata: {json.dumps(current)}\n\n"
                return
            yield ": keep-alive\n\n"
            await asyncio.to_thread(scan_progress.wait, 1.0)

    return StreamingResponse(generate(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


@router.get("/scan-batches/{batch_id}/progress")
def batch_progress_poll(batch_id: int, db: Session = Depends(get_db)):
    batch = db.get(ScanBatch, batch_id)
    if not batch:
        raise HTTPException(404, "Scan batch not found")
    return {
        "batch_id": batch.id, "status": batch.status, "total_services": batch.total_services,
        "completed_services": batch.completed_services, "progress_percent": batch.progress_percent,
        "overall_progress": batch.progress_percent,
        "current_service": batch.current_service, "scan_ids": json.loads(batch.scan_ids_json),
        "error": batch.error,
    }


@router.get("/scan-batches/{batch_id}/events")
@router.get("/scan-batches/{batch_id}/progress/stream")
async def batch_progress_events(batch_id: int, db: Session = Depends(get_db)):
    if not db.get(ScanBatch, batch_id):
        raise HTTPException(404, "Scan batch not found")

    async def generate():
        sequence = 0
        while True:
            events = scan_progress.after(-batch_id, sequence)
            for event in events:
                sequence = event["sequence"]
                yield f"id: {sequence}\nevent: progress\ndata: {json.dumps(event)}\n\n"
                if event.get("status") in {"completed", "failed"} and event.get("progress_percent") == 100:
                    return
            with SessionLocal() as session:
                batch_row = session.get(ScanBatch, batch_id)
                batch = {"batch_id": batch_id, "status": batch_row.status,
                         "progress_percent": batch_row.progress_percent,
                         "completed_services": batch_row.completed_services,
                         "total_services": batch_row.total_services,
                         "current_service": batch_row.current_service,
                         "scan_ids": json.loads(batch_row.scan_ids_json), "error": batch_row.error}
            if batch["status"] in {"completed", "failed"}:
                yield f"event: progress\ndata: {json.dumps(batch)}\n\n"
                return
            yield ": keep-alive\n\n"
            await asyncio.to_thread(scan_progress.wait, 1.0)

    return StreamingResponse(generate(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


@router.get("/scans/progress/latest")
def latest_scan_progress(db: Session = Depends(get_db)):
    batch = db.scalar(select(ScanBatch).order_by(ScanBatch.id.desc()))
    if batch:
        return batch_progress_poll(batch.id, db)
    scan = db.scalar(select(ScanSession).order_by(ScanSession.id.desc()))
    return _scan_progress_payload(scan.id) if scan else {"status": "empty"}
