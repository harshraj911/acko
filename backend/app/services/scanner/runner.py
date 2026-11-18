import json
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    ActivityLog, Dependency, DependencyRelationship, Finding, FindingEvent, FindingObservation,
    ScanBatch, ScanChange, ScanFile, ScanResult, ScanSession, Service, VulnerabilityAdvisory,
    VulnerabilityAffectedRange, WebhookDelivery,
)
from app.services.scanner.parser import ParsedPackage, scan_manifests
from app.services.risk_engine.scoring import assess_risk, default_due_date
from app.services.remediation.recommendations import recommendation_for
from app.services.versioning.ranges import is_affected
from app.services.webhooks.delivery import deliver_webhook
from app.services.scanner.progress import scan_progress


def _record(db: Session, scan: ScanSession, package: ParsedPackage) -> ScanResult:
    dependency = db.scalar(select(Dependency).where(
        Dependency.ecosystem == package.ecosystem,
        Dependency.normalized_name == package.normalized_name,
    ))
    if dependency is None:
        dependency = Dependency(
            ecosystem=package.ecosystem,
            normalized_name=package.normalized_name,
            display_name=package.name,
        )
        db.add(dependency)
        db.flush()
    result = ScanResult(
        scan_session_id=scan.id,
        dependency_id=dependency.id,
        instance_key=package.instance_key,
        package_path=package.package_path,
        version=package.version,
        declared_specifier=package.specifier,
        direct=package.direct,
        dev_only=package.dev_only,
        resolved=package.resolved,
        verification_state="verified" if package.resolved else "unverified",
        manifest_file=package.manifest_file,
    )
    db.add(result)
    db.flush()
    return result


def _range_map(db: Session) -> dict[tuple[str, str], list[tuple[VulnerabilityAdvisory, list[dict]]]]:
    grouped: dict[tuple[str, str, str], tuple[VulnerabilityAdvisory, list[list[dict]]]] = {}
    rows = db.execute(
        select(VulnerabilityAffectedRange, VulnerabilityAdvisory)
        .join(VulnerabilityAdvisory, VulnerabilityAdvisory.id == VulnerabilityAffectedRange.advisory_id)
    ).all()
    for affected, advisory in rows:
        key = (affected.ecosystem.lower(), affected.normalized_name, advisory.id)
        grouped.setdefault(key, (advisory, []))[1].append(json.loads(affected.events_json))
    result: dict[tuple[str, str], list[tuple[VulnerabilityAdvisory, list[list[dict]]]]] = defaultdict(list)
    for (ecosystem, package_name, _), item in grouped.items():
        result[(ecosystem, package_name)].append(item)
    return result


def scan_service(db: Session, service: Service, scan_id: int | None = None,
                 batch_id: int | None = None, batch_index: int = 0,
                 batch_total: int = 1) -> ScanSession:
    if not service.root_path:
        raise ValueError(f"Service {service.name} has no configured root_path")
    root = Path(service.root_path)
    if not root.is_dir():
        raise FileNotFoundError(f"Service path not found: {root}")
    previous_scan = db.scalar(select(ScanSession).where(
        ScanSession.service_id == service.id,
        ScanSession.status == "completed",
    ).order_by(ScanSession.id.desc()))
    previous_findings = db.scalars(select(Finding).where(Finding.service_id == service.id)).all()
    previous_finding_state = {
        finding.id: {"status": finding.status, "last_seen_scan_id": finding.last_seen_scan_id}
        for finding in previous_findings
    }
    started = time.monotonic()
    is_new_scan = scan_id is None
    scan = ScanSession(service_id=service.id) if is_new_scan else db.get(ScanSession, scan_id)
    if scan is None:
        raise ValueError(f"Scan session {scan_id} not found")
    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    db.add(scan)
    db.commit()
    scan_id = scan.id
    db.add(ActivityLog(entity_type="scan", entity_id=str(scan_id), event_type="scan.started", service_id=service.id))
    db.commit()
    scan = db.get(ScanSession, scan_id)
    started_at = scan.started_at
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    package_total = 1
    batch_total = 1

    def progress(status: str, current_file: str | None, packages: int, vulns: int):
        nonlocal scan
        scan.current_file = current_file
        scan.packages_inspected = packages
        scan.vulnerabilities_discovered = vulns
        scan.progress_percent = min(99.0, round(packages / max(package_total, 1) * 100, 2)) if status == "running" else 100.0
        db.commit()
        db.expire_all()
        scan = db.get(ScanSession, scan_id)
        overall = ((batch_index + scan.progress_percent / 100) / max(batch_total, 1) * 100) if batch_id else scan.progress_percent
        progress_event = dict(
            scan_id=scan.id,
            batch_id=batch_id,
            service_id=service.id,
            current_service=service.name,
            current_file=current_file,
            packages_inspected=packages,
            vulnerabilities_discovered=vulns,
            progress_percent=round(overall, 2),
            elapsed_seconds=(datetime.now(timezone.utc) - started_at).total_seconds(),
            status=status,
        )
        scan_progress.publish(scan_id, **progress_event)
        if batch_id:
            scan_progress.publish_batch(batch_id, **progress_event)

    try:
        files = [path for path in (root / "package.json", root / "package-lock.json",
                                   root / "requirements.txt", root / "requirements-dev.txt",
                                   root / "requirements.lock") if path.is_file()]
        file_records = []
        for path in files:
            record = ScanFile(scan_session_id=scan.id, file_path=path.name, status="pending")
            db.add(record)
            file_records.append(record)
        db.flush()
        db.commit()
        db.expire_all()
        scan = db.get(ScanSession, scan_id)
        current_file = None
        inspected_count = 0

        def on_file(file_name: str):
            nonlocal current_file, inspected_count
            current_file = file_name
            record = next((item for item in file_records if item.file_path == file_name), None)
            if record:
                record.status = "processing"
            db.commit()
            progress("running", file_name, inspected_count, 0)

        parsed = scan_manifests(root, on_file)
        package_total = max(len(parsed), 1)
        if batch_id:
            batch = db.get(ScanBatch, batch_id)
            if batch:
                batch_total = batch.total_services
                batch.current_service = service.name
                batch.status = "running"
                batch.progress_percent = round(batch_index / max(batch_total, 1) * 100, 2)
                db.commit()
        progress("running", files[0].name if files else None, 0, 0)
        result_by_key: dict[str, ScanResult] = {}
        instance_by_name = {package.normalized_name: package.instance_key for package in parsed}
        instance_by_path = {package.package_path: package.instance_key for package in parsed}
        for package in parsed:
            result = _record(db, scan, package)
            result_by_key[package.instance_key] = result
        db.flush()

        for package in parsed:
            parent_instances = [
                parent if parent in result_by_key else (
                    f"npm:{parent}" if package.ecosystem == "npm" and f"npm:{parent}" in result_by_key
                    else instance_by_path.get(parent, instance_by_name.get(parent))
                )
                for parent in package.parents
            ]
            for parent_instance in filter(None, parent_instances):
                parent = result_by_key.get(parent_instance)
                child = result_by_key[package.instance_key]
                if parent:
                    db.add(DependencyRelationship(
                        scan_session_id=scan.id,
                        parent_result_id=parent.id,
                        child_result_id=child.id,
                        direct=False,
                    ))
            if package.direct:
                db.add(DependencyRelationship(
                    scan_session_id=scan.id,
                    parent_result_id=None,
                    child_result_id=result_by_key[package.instance_key].id,
                    direct=True,
                ))
        db.flush()

        current_by_instance = {package.instance_key: package for package in parsed}
        if previous_scan:
            old_rows = db.execute(
                select(ScanResult, Dependency)
                .join(Dependency, Dependency.id == ScanResult.dependency_id)
                .where(ScanResult.scan_session_id == previous_scan.id)
            ).all()
            old_by_instance = {result.instance_key: (result, dep) for result, dep in old_rows}
            for instance_key in sorted(current_by_instance.keys() - old_by_instance.keys()):
                package = current_by_instance[instance_key]
                db.add(ScanChange(scan_session_id=scan.id, change_type="package_added", entity_key=instance_key,
                                  after_json=json.dumps({"name": package.name, "version": package.version, "dev_only": package.dev_only})))
            for instance_key in sorted(old_by_instance.keys() - current_by_instance.keys()):
                old, dep = old_by_instance[instance_key]
                db.add(ScanChange(scan_session_id=scan.id, change_type="package_removed", entity_key=instance_key,
                                  before_json=json.dumps({"name": dep.display_name, "version": old.version, "dev_only": old.dev_only})))
            for instance_key in sorted(current_by_instance.keys() & old_by_instance.keys()):
                package = current_by_instance[instance_key]
                old, dep = old_by_instance[instance_key]
                current = result_by_key[instance_key]
                if old.version != current.version:
                    db.add(ScanChange(scan_session_id=scan.id, change_type="version_changed", entity_key=instance_key,
                                      before_json=json.dumps({"version": old.version}),
                                      after_json=json.dumps({"version": current.version})))
                if old.direct != current.direct or old.dev_only != current.dev_only:
                    db.add(ScanChange(scan_session_id=scan.id, change_type="scope_changed", entity_key=instance_key,
                                      before_json=json.dumps({"direct": old.direct, "dev_only": old.dev_only}),
                                      after_json=json.dumps({"direct": current.direct, "dev_only": current.dev_only})))

            def relationship_set(scan_id: int):
                rels = db.scalars(select(DependencyRelationship).where(DependencyRelationship.scan_session_id == scan_id)).all()
                output = set()
                for rel in rels:
                    child = db.get(ScanResult, rel.child_result_id)
                    parent = db.get(ScanResult, rel.parent_result_id) if rel.parent_result_id else None
                    if child:
                        output.add((parent.instance_key if parent else None, child.instance_key, rel.direct))
                return output

            old_edges = relationship_set(previous_scan.id)
            new_edges = relationship_set(scan.id)
            for edge in sorted(new_edges - old_edges, key=str):
                db.add(ScanChange(scan_session_id=scan.id, change_type="relationship_added", entity_key=str(edge),
                                  after_json=json.dumps({"parent": edge[0], "child": edge[1], "direct": edge[2]})))
            for edge in sorted(old_edges - new_edges, key=str):
                db.add(ScanChange(scan_session_id=scan.id, change_type="relationship_removed", entity_key=str(edge),
                                  before_json=json.dumps({"parent": edge[0], "child": edge[1], "direct": edge[2]})))

        advisories = _range_map(db)
        matched_finding_ids: set[int] = set()
        vulnerable_count = unverified_count = 0
        vulnerabilities_so_far = 0
        file_package_counts: dict[str, int] = defaultdict(int)
        for package_index, package in enumerate(parsed, start=1):
            inspected_count = package_index - 1
            progress("running", package.manifest_file, package_index - 1, vulnerabilities_so_far)
            file_package_counts[package.manifest_file] += 1
            scan_result = result_by_key[package.instance_key]
            candidates = advisories.get((package.ecosystem.lower(), package.normalized_name), [])
            if not package.resolved or package.version is None:
                for advisory, _ in candidates:
                    if advisory.withdrawn:
                        continue
                    existing = db.scalar(select(Finding).where(
                        Finding.service_id == service.id,
                        Finding.instance_key == package.instance_key,
                        Finding.advisory_id == advisory.id,
                        Finding.status != "resolved",
                    ))
                    if existing:
                        matched_finding_ids.add(existing.id)
                    db.add(FindingObservation(
                        scan_result_id=scan_result.id,
                        advisory_id=advisory.id,
                        state="unverified",
                    ))
                    unverified_count += 1
                continue
            for advisory, range_events in candidates:
                if advisory.withdrawn or not is_affected(
                    package.ecosystem, package.version,
                    [{"events": events} for events in range_events],
                ):
                    continue
                existing = db.scalar(select(Finding).where(
                    Finding.service_id == service.id,
                    Finding.instance_key == package.instance_key,
                    Finding.advisory_id == advisory.id,
                ))
                now = datetime.now(timezone.utc)
                if existing is None:
                    existing = Finding(
                        service_id=service.id,
                        dependency_id=scan_result.dependency_id,
                        advisory_id=advisory.id,
                        instance_key=package.instance_key,
                        first_scan_id=scan.id,
                        last_seen_scan_id=scan.id,
                        current_scan_result_id=scan_result.id,
                        installed_version=package.version,
                        dev_only=package.dev_only,
                        source_severity=advisory.source_severity,
                        priority="Low",
                        assigned_owner=service.owner,
                        due_date=default_due_date("Low", now),
                        status="open",
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                    db.add(existing)
                    db.flush()
                    recommendation = recommendation_for(db, existing, service, db.get(Dependency, existing.dependency_id), advisory)
                    existing.fixed_version = recommendation["fixed_version"]
                    existing.upgrade_complexity = recommendation["upgrade_complexity"]
                    assessment = assess_risk(
                        advisory.source_severity, service.tier, service.internet_facing,
                        recommendation["fix_available"], recommendation["upgrade_complexity"], package.dev_only,
                    )
                    existing.priority = assessment.priority
                    existing.risk_score = assessment.score
                    existing.risk_breakdown_json = json.dumps(assessment.breakdown)
                    existing.due_date = default_due_date(assessment.priority, now)
                    db.add(FindingEvent(
                        finding_id=existing.id, event_type="created", actor="system",
                        after_json=json.dumps({"status": "Open", "owner": service.owner, "priority": assessment.priority,
                                               "risk_score": assessment.score, "due_date": existing.due_date.isoformat()}),
                        note="Finding created by dependency scan.", scan_id=scan.id,
                    ))
                    db.add(ActivityLog(
                        entity_type="finding", entity_id=str(existing.id),
                        event_type="finding.detected",
                        service_id=service.id, dependency_id=scan_result.dependency_id, finding_id=existing.id,
                        details_json=json.dumps({"service": service.name, "advisory": advisory.id}),
                    ))
                    critical = assessment.priority == "Critical"
                    event_type = "vulnerability.critical" if critical else "finding.high_priority" if assessment.priority == "High" else None
                    if event_type:
                        deliver_webhook(db, event_type, existing, service,
                                        db.get(Dependency, existing.dependency_id), advisory)
                else:
                    was_resolved = existing.status == "resolved"
                    existing.last_seen_scan_id = scan.id
                    existing.current_scan_result_id = scan_result.id
                    existing.installed_version = package.version
                    existing.dev_only = package.dev_only
                    existing.source_severity = advisory.source_severity
                    recommendation = recommendation_for(db, existing, service, db.get(Dependency, existing.dependency_id), advisory)
                    existing.fixed_version = recommendation["fixed_version"]
                    existing.upgrade_complexity = recommendation["upgrade_complexity"]
                    assessment = assess_risk(
                        advisory.source_severity, service.tier, service.internet_facing,
                        recommendation["fix_available"], recommendation["upgrade_complexity"], package.dev_only,
                    )
                    existing.priority = assessment.priority
                    existing.risk_score = assessment.score
                    existing.risk_breakdown_json = json.dumps(assessment.breakdown)
                    existing.due_date = existing.due_date or default_due_date(assessment.priority, now)
                    existing.last_seen_at = now
                    existing.resolved_at = None
                    existing.resolution_reason = None
                    if was_resolved:
                        existing.status = "open"
                        existing.assigned_owner = existing.assigned_owner or service.owner
                        db.add(FindingEvent(
                            finding_id=existing.id, event_type="reappeared", actor="system",
                            before_json=json.dumps({"status": "Resolved"}),
                            after_json=json.dumps({"status": "Open", "version": package.version}),
                            note=f"Vulnerable dependency reappeared in scan {scan.id}.", scan_id=scan.id,
                        ))
                        db.add(ActivityLog(
                            entity_type="finding", entity_id=str(existing.id),
                            event_type="finding.reappeared",
                            service_id=service.id, dependency_id=scan_result.dependency_id, finding_id=existing.id,
                            details_json=json.dumps({"scan_id": scan.id, "version": package.version}),
                        ))
                        deliver_webhook(db, "finding.reappeared", existing, service,
                                        db.get(Dependency, existing.dependency_id), advisory,
                                        dedupe_key=f"finding.reappeared:{existing.id}:{scan.id}")
                    critical = assessment.priority == "Critical"
                    if critical or assessment.priority == "High":
                        event_type = "vulnerability.critical" if critical else "finding.high_priority"
                        deliver_webhook(
                            db, event_type, existing, service,
                            db.get(Dependency, existing.dependency_id), advisory,
                            dedupe_key=f"{event_type}:{existing.id}",
                        )
                matched_finding_ids.add(existing.id)
                db.add(FindingObservation(
                    scan_result_id=scan_result.id,
                    advisory_id=advisory.id,
                    state="vulnerable",
                    finding_id=existing.id,
                ))
                vulnerable_count += 1
                vulnerabilities_so_far += 1

        for file_record in file_records:
            file_record.status = "completed"
            file_record.packages_found = file_package_counts.get(file_record.file_path, 0)
            file_record.completed_at = datetime.now(timezone.utc)
        db.flush()

        # Only findings previously belonging to this service can be resolved by its completed snapshot.
        previous = db.scalars(select(Finding).where(
            Finding.service_id == service.id,
            Finding.status != "resolved",
        )).all()
        for finding in previous:
            if finding.id in matched_finding_ids:
                continue
            advisory = db.get(VulnerabilityAdvisory, finding.advisory_id)
            observed_result = next((
                result_by_key.get(package.instance_key)
                for package in parsed
                if package.instance_key == finding.instance_key
            ), None)
            if observed_result and not observed_result.resolved:
                db.add(FindingObservation(
                    scan_result_id=observed_result.id,
                    advisory_id=finding.advisory_id,
                    state="unverified",
                    finding_id=finding.id,
                ))
                continue
            reason = "withdrawn" if advisory and advisory.withdrawn else "scan_clear"
            prior_status = finding.status
            finding.status = "resolved"
            finding.resolution_reason = reason
            finding.resolved_at = datetime.now(timezone.utc)
            finding.verification_scan_id = scan.id
            resolution_note = f"Automatically resolved by verification scan {scan.id}: vulnerable package is no longer present."
            finding.resolution_info = resolution_note
            db.add(FindingEvent(
                finding_id=finding.id, event_type="resolved", actor="system",
                before_json=json.dumps({"status": prior_status.title()}),
                after_json=json.dumps({"status": "Resolved", "scan_id": scan.id, "reason": reason}),
                note=resolution_note, scan_id=scan.id,
            ))
            db.add(ActivityLog(
                entity_type="finding", entity_id=str(finding.id),
                event_type=f"finding.{reason}",
                service_id=service.id, dependency_id=finding.dependency_id, finding_id=finding.id,
                details_json=json.dumps({"scan_id": scan.id}),
            ))
            advisory = db.get(VulnerabilityAdvisory, finding.advisory_id)
            deliver_webhook(db, "finding.resolved", finding, service,
                            db.get(Dependency, finding.dependency_id), advisory,
                            dedupe_key=f"finding.resolved:{finding.id}:{scan.id}")

        if previous_scan:
            current_active_ids = set(matched_finding_ids)
            prior_active_ids = {
                finding_id for finding_id, state in previous_finding_state.items()
                if state["status"] != "resolved"
            }
            for finding_id in sorted(current_active_ids - prior_active_ids):
                kind = "vulnerability_reappeared" if previous_finding_state.get(finding_id, {}).get("status") == "resolved" else "vulnerability_new"
                db.add(ScanChange(scan_session_id=scan.id, change_type=kind, entity_key=str(finding_id), finding_id=finding_id))
            resolved_ids = {
                finding_id for finding_id in prior_active_ids
                if (finding := db.get(Finding, finding_id)) and finding.status == "resolved"
            }
            for finding_id in sorted(resolved_ids):
                db.add(ScanChange(scan_session_id=scan.id, change_type="vulnerability_resolved", entity_key=str(finding_id), finding_id=finding_id))

        scan.status = "completed"
        scan.package_count = len(parsed)
        scan.vulnerable_count = vulnerable_count
        scan.unverified_count = unverified_count
        scan.packages_inspected = len(parsed)
        scan.vulnerabilities_discovered = vulnerable_count
        scan.progress_percent = 100
        scan.duration_seconds = time.monotonic() - started
        scan.completed_at = datetime.now(timezone.utc)
        db.add(ActivityLog(
            entity_type="scan", entity_id=str(scan.id), event_type="scan.completed",
            service_id=service.id,
            details_json=json.dumps({"service": service.name, "packages": len(parsed)}),
        ))
        for finding in db.scalars(select(Finding).where(
            Finding.service_id == service.id,
            Finding.status.in_(("open", "in_progress")),
            Finding.due_date.is_not(None),
            Finding.due_date < datetime.now(timezone.utc),
        )).all():
            existing_delivery = db.scalar(select(WebhookDelivery.id).where(
                WebhookDelivery.dedupe_key == f"finding.overdue:{finding.id}",
            ))
            if existing_delivery:
                continue
            delivery = deliver_webhook(
                db, "finding.overdue", finding, service,
                db.get(Dependency, finding.dependency_id),
                db.get(VulnerabilityAdvisory, finding.advisory_id),
            )
            if delivery:
                db.add(FindingEvent(
                    finding_id=finding.id, event_type="overdue_notified", actor="system",
                    after_json=json.dumps({"delivery_id": delivery.id}),
                    note="Overdue notification evaluated during scan.", scan_id=scan.id,
                ))
        db.commit()
        db.refresh(scan)
        progress("completed", None, len(parsed), vulnerable_count)
        return scan
    except Exception as exc:
        db.rollback()
        for file_record in db.scalars(select(ScanFile).where(ScanFile.scan_session_id == scan.id,
                                                           ScanFile.status == "pending")):
            file_record.status = "failed"
            file_record.completed_at = datetime.now(timezone.utc)
        failed = db.get(ScanSession, scan.id)
        if failed:
            failed.status = "failed"
            failed.error = str(exc)
            failed.completed_at = datetime.now(timezone.utc)
            failed.duration_seconds = time.monotonic() - started
            db.commit()
            db.add(ActivityLog(
                entity_type="scan", entity_id=str(scan.id), event_type="scan.failed",
                service_id=service.id, details_json=json.dumps({"error": str(exc)}),
            ))
            db.commit()
            progress("failed", None, failed.packages_inspected, failed.vulnerabilities_discovered)
        raise


def scan_all(db: Session) -> list[ScanSession]:
    services = db.scalars(select(Service).order_by(Service.name)).all()
    return [scan_service(db, service) for service in services]


def dependency_chain(db: Session, scan_id: int, result: ScanResult) -> list[str]:
    chain = [result.package_path]
    current_id = result.id
    while True:
        edge = db.scalar(select(DependencyRelationship).where(
            DependencyRelationship.scan_session_id == scan_id,
            DependencyRelationship.child_result_id == current_id,
        ).order_by(DependencyRelationship.direct.desc()))
        if not edge or edge.parent_result_id is None:
            break
        parent = db.get(ScanResult, edge.parent_result_id)
        if not parent:
            break
        chain.append(parent.package_path)
        current_id = parent.id
    return list(reversed(chain))
