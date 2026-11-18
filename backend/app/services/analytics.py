from collections import Counter, defaultdict
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    ActivityLog, Dependency, Finding, FindingEvent, ScanResult, ScanSession, Service,
    VulnerabilityAdvisory,
)


def _finding_rows(db: Session, dev_only: bool | None = None):
    query = select(Finding, Service, Dependency, VulnerabilityAdvisory).join(
        Service, Service.id == Finding.service_id,
    ).join(Dependency, Dependency.id == Finding.dependency_id).join(
        VulnerabilityAdvisory, VulnerabilityAdvisory.id == Finding.advisory_id,
    )
    if dev_only is not None:
        query = query.where(Finding.dev_only.is_(dev_only))
    return db.execute(query).all()


def _latest_scans(db: Session):
    latest = select(func.max(ScanSession.id).label("scan_id")).where(
        ScanSession.status == "completed",
    ).group_by(ScanSession.service_id).subquery()
    return db.scalars(select(ScanSession).join(latest, latest.c.scan_id == ScanSession.id)).all()


def _severity(value: str | None) -> str:
    return "Medium" if (value or "").upper() == "MODERATE" else (value or "Unspecified").title()


def _is_overdue(finding: Finding, now: datetime) -> bool:
    if not finding.due_date:
        return False
    due = finding.due_date.replace(tzinfo=timezone.utc) if finding.due_date.tzinfo is None else finding.due_date
    return due < now


def analytics_data(db: Session, dev_only: bool | None = None) -> dict:
    rows = _finding_rows(db, dev_only)
    severity = Counter(_severity(f.source_severity) for f, *_ in rows if f.status != "resolved")
    by_service = Counter(s.name for f, s, *_ in rows if f.status != "resolved")
    open_by_day: dict[str, int] = defaultdict(int)
    resolved_by_day: dict[str, int] = defaultdict(int)
    events_query = select(FindingEvent).order_by(FindingEvent.created_at, FindingEvent.id)
    if dev_only is not None:
        events_query = events_query.join(Finding, Finding.id == FindingEvent.finding_id).where(Finding.dev_only.is_(dev_only))
    for event in db.scalars(events_query).all():
        day = event.created_at.date().isoformat()
        if event.event_type == "created":
            open_by_day[day] += 1
        if event.event_type == "resolved":
            resolved_by_day[day] += 1
    resolution_durations = [
        max(0.0, ((f.resolved_at.replace(tzinfo=timezone.utc) if f.resolved_at.tzinfo is None else f.resolved_at)
                  - (f.first_seen_at.replace(tzinfo=timezone.utc) if f.first_seen_at.tzinfo is None else f.first_seen_at)).total_seconds())
        for f, *_ in rows if f.status == "resolved" and f.resolved_at and f.first_seen_at
    ]
    overdue = [f for f, *_ in rows if f.status in {"open", "in_progress"} and _is_overdue(f, datetime.now(timezone.utc))]
    latest_scans = _latest_scans(db)
    package_total = sum(scan.package_count for scan in latest_scans)
    return {
        "vulnerabilities_by_severity": dict(severity),
        "vulnerabilities_by_service": dict(by_service),
        "open_findings_over_time": _cumulative_series(open_by_day),
        "resolved_findings_over_time": _cumulative_series(resolved_by_day),
        "average_resolution_time_seconds": sum(resolution_durations) / len(resolution_durations) if resolution_durations else None,
        "overdue_findings": len(overdue),
        "total_packages_scanned": package_total,
        "most_vulnerable_services": [
            {"service": name, "active_findings": count}
            for name, count in by_service.most_common()
        ],
        "dev_only": dev_only,
        "history_grouping": "calendar day from finding event timestamps; only days with recorded events are returned",
    }


def overview_data(db: Session, dev_only: bool | None = None) -> dict:
    rows = _finding_rows(db, dev_only)
    active = [(f, s, d, a) for f, s, d, a in rows if f.status != "resolved" and not a.withdrawn]
    now = datetime.now(timezone.utc)
    overdue = [f for f, *_ in rows if f.status in {"open", "in_progress"} and _is_overdue(f, now)]
    all_scans = db.scalars(select(ScanSession).order_by(ScanSession.started_at, ScanSession.id)).all()
    latest_scans = _latest_scans(db)
    latest_by_service = {scan.service_id: scan for scan in latest_scans}
    risk_trend = []
    event_days: dict[str, list[FindingEvent]] = defaultdict(list)
    events_query = select(FindingEvent).order_by(FindingEvent.created_at, FindingEvent.id)
    if dev_only is not None:
        events_query = events_query.join(Finding, Finding.id == FindingEvent.finding_id).where(Finding.dev_only.is_(dev_only))
    for event in db.scalars(events_query).all():
        event_days[event.created_at.date().isoformat()].append(event)
    running = 0
    for day, events in sorted(event_days.items()):
        for event in events:
            if event.event_type == "created":
                running += 1
            elif event.event_type == "resolved":
                running = max(0, running - 1)
        risk_trend.append({"date": day, "active_findings": running})

    severity_counts = Counter(_severity(f.source_severity) for f, *_ in active)
    service_counts = Counter(s.name for f, s, *_ in active)
    recent = sorted(active, key=lambda row: row[0].first_seen_at, reverse=True)[:10]
    service_reasons: dict[int, list[str]] = defaultdict(list)
    for finding, service, dependency, advisory in active:
        if finding.priority in {"Critical", "High"}:
            service_reasons[service.id].append(
                f"{finding.priority} {advisory.id} in {dependency.display_name} {finding.installed_version}"
            )
    attention = []
    for service_id, reasons in service_reasons.items():
        service = db.get(Service, service_id)
        attention.append({"service_id": service_id, "service": service.name, "reasons": reasons})
    attention.sort(key=lambda item: (0 if any(reason.startswith("Critical") for reason in item["reasons"]) else 1, item["service"]))
    activity = db.scalars(select(ActivityLog).where(ActivityLog.event_type.in_(
        ("finding.scan_clear", "finding.withdrawn", "finding.resolved", "finding.reappeared"),
    )).order_by(ActivityLog.created_at.desc()).limit(10)).all()
    latest_scan = max(all_scans, key=lambda scan: scan.completed_at or scan.started_at) if all_scans else None
    return {
        "total_services": db.scalar(select(func.count(Service.id))) or 0,
        "total_packages_scanned": sum(scan.package_count for scan in latest_scans),
        "total_vulnerabilities": len(active),
        "critical_vulnerabilities": sum(f.priority == "Critical" for f, *_ in active),
        "open_findings": sum(f.status in {"open", "in_progress"} for f, *_ in active),
        "resolved_findings": sum(f.status == "resolved" for f, *_ in rows),
        "overdue_findings": len(overdue),
        "severity_distribution": dict(severity_counts),
        "risk_trend": risk_trend,
        "most_affected_services": [{"service": name, "active_findings": count} for name, count in service_counts.most_common(5)],
        "recent_vulnerabilities": [{"finding_id": f.id, "service": s.name, "package": d.display_name,
                                     "advisory_id": a.id, "discovered_at": f.first_seen_at, "dev_only": f.dev_only}
                                    for f, s, d, a in recent],
        "recent_remediation_activity": [{"event_type": event.event_type, "finding_id": event.finding_id,
                                         "service_id": event.service_id, "created_at": event.created_at}
                                        for event in activity],
        "services_needing_attention": attention,
        "latest_scan": ({"id": latest_scan.id, "service_id": latest_scan.service_id,
                         "status": latest_scan.status, "started_at": latest_scan.started_at,
                         "completed_at": latest_scan.completed_at, "package_count": latest_scan.package_count}
                        if latest_scan else None),
        "dev_only": dev_only,
        "history_grouping": "calendar day; only observed event days are returned",
    }


def _cumulative_series(daily: dict[str, int]):
    output = []
    running = 0
    for day, delta in sorted(daily.items()):
        running += delta
        output.append({"date": day, "count": running})
    return output
