import json
import threading
from datetime import datetime, timezone

from sqlalchemy import select

from app.core.config import settings
from app.database.session import SessionLocal
from app.models import ActivityLog, Dependency, Finding, FindingEvent, Service, VulnerabilityAdvisory, WebhookDelivery
from app.services.webhooks.delivery import deliver_webhook


def check_overdue_once(now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    delivered = 0
    with SessionLocal() as db:
        findings = db.scalars(select(Finding).where(
            Finding.status.in_(("open", "in_progress")),
            Finding.due_date.is_not(None),
        )).all()
        for finding in findings:
            due = finding.due_date.replace(tzinfo=timezone.utc) if finding.due_date.tzinfo is None else finding.due_date
            if due >= now:
                continue
            dedupe_key = f"finding.overdue:{finding.id}"
            if db.scalar(select(WebhookDelivery.id).where(WebhookDelivery.dedupe_key == dedupe_key)):
                continue
            service = db.get(Service, finding.service_id)
            dependency = db.get(Dependency, finding.dependency_id)
            advisory = db.get(VulnerabilityAdvisory, finding.advisory_id)
            if not service or not dependency or not advisory:
                continue
            delivery = deliver_webhook(db, "finding.overdue", finding, service, dependency, advisory, dedupe_key)
            db.add(FindingEvent(
                finding_id=finding.id, event_type="overdue_notified", actor="scheduler",
                after_json=json.dumps({"delivery_id": delivery.id if delivery else None}),
                note="Overdue notification evaluated by the periodic background check.",
            ))
            db.add(ActivityLog(
                entity_type="finding", entity_id=str(finding.id), event_type="finding.overdue_notified",
                service_id=service.id, dependency_id=dependency.id, finding_id=finding.id,
                details_json=json.dumps({"delivery_id": delivery.id if delivery else None}),
            ))
            delivered += int(bool(delivery))
        db.commit()
    return delivered


class OverdueScheduler:
    def __init__(self):
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="overdue-checker", daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.wait(max(settings.overdue_check_seconds, 1)):
            try:
                check_overdue_once()
            except Exception:
                continue

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)


overdue_scheduler = OverdueScheduler()
