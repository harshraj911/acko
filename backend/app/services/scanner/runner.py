import json
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    ActivityLog, Dependency, DependencyRelationship, Finding, FindingObservation,
    ScanResult, ScanSession, Service, VulnerabilityAdvisory,
    VulnerabilityAffectedRange,
)
from app.services.scanner.parser import ParsedPackage, scan_manifests
from app.services.risk_engine.scoring import finding_priority
from app.services.versioning.ranges import is_affected


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


def scan_service(db: Session, service: Service) -> ScanSession:
    if not service.root_path:
        raise ValueError(f"Service {service.name} has no configured root_path")
    root = Path(service.root_path)
    if not root.is_dir():
        raise FileNotFoundError(f"Service path not found: {root}")
    started = time.monotonic()
    scan = ScanSession(service_id=service.id, status="running")
    db.add(scan)
    db.commit()
    try:
        parsed = scan_manifests(root)
        result_by_key: dict[str, ScanResult] = {}
        parsed_by_key = {package.instance_key: package for package in parsed}
        instance_by_name = {package.normalized_name: package.instance_key for package in parsed}
        for package in parsed:
            result = _record(db, scan, package)
            result_by_key[package.instance_key] = result
        db.flush()

        parent_for: dict[str, str] = {}
        for package in parsed:
            parent_instances = [
                parent if parent in result_by_key else instance_by_name.get(parent)
                for parent in package.parents
            ]
            for parent_instance in filter(None, parent_instances):
                parent_for[package.instance_key] = parent_instance
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

        advisories = _range_map(db)
        matched_finding_ids: set[int] = set()
        vulnerable_count = unverified_count = 0
        for package in parsed:
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
                        priority=finding_priority(
                            advisory.source_severity, service.tier, service.internet_facing, package.dev_only,
                        ),
                        status="open",
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                    db.add(existing)
                    db.flush()
                    db.add(ActivityLog(
                        entity_type="finding", entity_id=str(existing.id),
                        event_type="finding.detected",
                        details_json=json.dumps({"service": service.name, "advisory": advisory.id}),
                    ))
                else:
                    existing.last_seen_scan_id = scan.id
                    existing.current_scan_result_id = scan_result.id
                    existing.installed_version = package.version
                    existing.dev_only = package.dev_only
                    existing.source_severity = advisory.source_severity
                    existing.priority = finding_priority(
                        advisory.source_severity, service.tier, service.internet_facing, package.dev_only,
                    )
                    existing.last_seen_at = now
                    existing.resolved_at = None
                    existing.resolution_reason = None
                    if existing.status == "resolved":
                        existing.status = "open"
                        db.add(ActivityLog(
                            entity_type="finding", entity_id=str(existing.id),
                            event_type="finding.reappeared",
                            details_json=json.dumps({"scan_id": scan.id, "version": package.version}),
                        ))
                matched_finding_ids.add(existing.id)
                db.add(FindingObservation(
                    scan_result_id=scan_result.id,
                    advisory_id=advisory.id,
                    state="vulnerable",
                    finding_id=existing.id,
                ))
                vulnerable_count += 1

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
            finding.status = "resolved"
            finding.resolution_reason = reason
            finding.resolved_at = datetime.now(timezone.utc)
            db.add(ActivityLog(
                entity_type="finding", entity_id=str(finding.id),
                event_type=f"finding.{reason}",
                details_json=json.dumps({"scan_id": scan.id}),
            ))

        scan.status = "completed"
        scan.package_count = len(parsed)
        scan.vulnerable_count = vulnerable_count
        scan.unverified_count = unverified_count
        scan.duration_seconds = time.monotonic() - started
        scan.completed_at = datetime.now(timezone.utc)
        db.add(ActivityLog(
            entity_type="scan", entity_id=str(scan.id), event_type="scan.completed",
            details_json=json.dumps({"service": service.name, "packages": len(parsed)}),
        ))
        db.commit()
        db.refresh(scan)
        return scan
    except Exception as exc:
        db.rollback()
        failed = db.get(ScanSession, scan.id)
        if failed:
            failed.status = "failed"
            failed.error = str(exc)
            failed.completed_at = datetime.now(timezone.utc)
            failed.duration_seconds = time.monotonic() - started
            db.commit()
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
