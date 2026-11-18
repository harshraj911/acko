import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from sqlalchemy import select

from app.database.session import SessionLocal
from app.models import ScanBatch, ScanSession, Service
from app.services.scanner.progress import scan_progress
from app.services.scanner.runner import scan_service


executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dependency-scan")


def _run_batch(batch_id: int, service_scan_ids: list[tuple[int, int]]) -> None:
    with SessionLocal() as db:
        batch = db.get(ScanBatch, batch_id)
        if not batch:
            return
        batch.status = "running"
        batch.started_at = datetime.now(timezone.utc)
        total = batch.total_services
        scan_ids = json.loads(batch.scan_ids_json)
        db.commit()
        scan_progress.publish_batch(batch_id, status="running", progress_percent=0,
                                    total_services=total, completed_services=0,
                                    current_service=None, scan_ids=scan_ids)
    for index, (service_id, scan_id) in enumerate(service_scan_ids):
        with SessionLocal() as db:
            service = db.get(Service, service_id)
            batch = db.get(ScanBatch, batch_id)
            if not service or not batch:
                continue
            batch.current_service = service.name
            service_name = service.name
            completed = batch.completed_services
            batch_progress = batch.progress_percent
            total = batch.total_services
            scan_ids = json.loads(batch.scan_ids_json)
            db.commit()
            scan_progress.publish_batch(batch_id, status="running", progress_percent=batch_progress,
                                        total_services=total, completed_services=completed,
                                        current_service=service_name, scan_ids=scan_ids)
        with SessionLocal() as scan_db:
            service_for_scan = scan_db.get(Service, service_id)
            try:
                scan_service(scan_db, service_for_scan, scan_id=scan_id, batch_id=batch_id,
                             batch_index=index, batch_total=len(service_scan_ids))
            except Exception as exc:
                scan_db.rollback()
                failed_scan = scan_db.get(ScanSession, scan_id)
                if failed_scan and failed_scan.status == "queued":
                    failed_scan.status = "failed"
                    failed_scan.error = str(exc)
                    failed_scan.completed_at = datetime.now(timezone.utc)
                    scan_db.commit()
        with SessionLocal() as db:
            scan = db.get(ScanSession, scan_id)
            if scan:
                scan_progress.publish(scan_id, scan_id=scan.id, batch_id=batch_id,
                                      service_id=service_id, current_service=service_name,
                                      current_file=scan.current_file,
                                      packages_inspected=scan.packages_inspected,
                                      vulnerabilities_discovered=scan.vulnerabilities_discovered,
                                      progress_percent=100,
                                      elapsed_seconds=scan.duration_seconds or 0,
                                      status="failed" if scan.status == "failed" else "completed",
                                      error=scan.error)
        with SessionLocal() as db:
            batch = db.get(ScanBatch, batch_id)
            batch.completed_services = index + 1
            batch.progress_percent = round((index + 1) / max(batch.total_services, 1) * 100, 2)
            completed = batch.completed_services
            total = batch.total_services
            pct = batch.progress_percent
            service_name = batch.current_service
            scan_ids = json.loads(batch.scan_ids_json)
            db.commit()
            scan_progress.publish_batch(batch_id, status="running", progress_percent=pct,
                                        total_services=total, completed_services=completed,
                                        current_service=service_name, scan_ids=scan_ids)
    with SessionLocal() as db:
        batch = db.get(ScanBatch, batch_id)
        if batch:
            scans = [db.get(ScanSession, scan_id) for _, scan_id in service_scan_ids]
            failures = [scan for scan in scans if not scan or scan.status == "failed"]
            batch.status = "failed" if failures else "completed"
            batch.error = "; ".join(scan.error or "scan failed" for scan in failures) or None
            batch.completed_at = datetime.now(timezone.utc)
            batch.progress_percent = 100
            total = batch.total_services
            completed = batch.completed_services
            service_name = batch.current_service
            scan_ids = json.loads(batch.scan_ids_json)
            status = batch.status
            error = batch.error
            scan_payloads = [
                {"scan_id": scan.id, "service_id": scan.service_id,
                 "packages_inspected": scan.packages_inspected,
                 "vulnerabilities_discovered": scan.vulnerabilities_discovered,
                 "duration_seconds": scan.duration_seconds,
                 "status": scan.status, "error": scan.error}
                for scan in scans if scan
            ]
            db.commit()
            scan_progress.publish_batch(batch_id, status=status, progress_percent=100,
                                        total_services=total, completed_services=completed,
                                        current_service=service_name, scan_ids=scan_ids, error=error,
                                        scans=scan_payloads)


def _execute_single(scan_id: int, service_id: int):
    with SessionLocal() as db:
        service = db.get(Service, service_id)
        if service:
            try:
                scan_service(db, service, scan_id=scan_id)
            except Exception:
                pass


def create_scan_job(service_ids: list[int]) -> tuple[ScanBatch, list[ScanSession]]:
    with SessionLocal() as db:
        services = db.scalars(select(Service).where(Service.id.in_(service_ids)).order_by(Service.name)).all()
        service_names = {service.id: service.name for service in services}
        batch = ScanBatch(status="queued", total_services=len(services), scan_ids_json="[]")
        db.add(batch)
        db.flush()
        sessions = [ScanSession(service_id=service.id, status="queued") for service in services]
        db.add_all(sessions)
        db.flush()
        scan_ids = [(service.id, session.id) for service, session in zip(services, sessions)]
        batch.scan_ids_json = json.dumps([scan_id for _, scan_id in scan_ids])
        result_ids = [session.id for session in sessions]
        scan_names = {service.id: service.name for service in services}
        batch_id = batch.id
        db.commit()
        db.refresh(batch)
        db.expunge(batch)
        detached_batch = batch
        scan_progress.publish_batch(batch_id, status="queued", progress_percent=0,
                                    total_services=len(scan_ids), completed_services=0,
                                    current_service=None, scan_ids=[scan_id for _, scan_id in scan_ids],
                                    services=[{"service_id": service_id, "name": scan_names[service_id],
                                               "scan_id": scan_id}
                                              for service_id, scan_id in scan_ids])
    executor.submit(_run_batch, detached_batch.id, scan_ids)
    with SessionLocal() as db:
        batch_copy = db.get(ScanBatch, detached_batch.id)
        scan_copies = [db.get(ScanSession, scan_id) for scan_id in result_ids]
        for item in [batch_copy, *scan_copies]:
            db.expunge(item)
        return batch_copy, scan_copies


def create_single_scan(service_id: int) -> ScanSession:
    with SessionLocal() as db:
        service = db.get(Service, service_id)
        if not service:
            raise ValueError("Service not found")
        scan = ScanSession(service_id=service_id, status="queued")
        db.add(scan)
        db.flush()
        scan_id = scan.id
        scan_progress.publish(scan.id, scan_id=scan.id, status="queued", current_service=service.name,
                              current_file=None, packages_inspected=0, vulnerabilities_discovered=0,
                              progress_percent=0, elapsed_seconds=0)
        db.commit()
    executor.submit(_execute_single, scan_id, service_id)
    with SessionLocal() as db:
        scan = db.get(ScanSession, scan_id)
        db.expunge(scan)
        return scan


def launch_initial_scan() -> int | None:
    with SessionLocal() as db:
        if db.scalar(select(ScanSession.id).limit(1)):
            return None
        services = db.scalars(select(Service).order_by(Service.name)).all()
        service_ids = [service.id for service in services]
    if not service_ids:
        return None
    batch, _ = create_scan_job(service_ids)
    return batch.id
