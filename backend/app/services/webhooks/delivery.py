import json

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Dependency, Finding, Service, VulnerabilityAdvisory, WebhookDelivery


def deliver_webhook(db: Session, event_type: str, finding: Finding, service: Service,
                    dependency: Dependency, advisory: VulnerabilityAdvisory,
                    dedupe_key: str | None = None) -> WebhookDelivery | None:
    key = dedupe_key or f"{event_type}:{finding.id}"
    existing = db.scalar(select(WebhookDelivery).where(WebhookDelivery.dedupe_key == key))
    if existing:
        return existing
    payload = {
        "event_type": event_type,
        "service": service.name,
        "package": dependency.display_name,
        "advisory_id": advisory.id,
        "severity": advisory.source_severity,
        "priority": finding.priority,
        "finding_id": finding.id,
        "reference": f"/findings/{finding.id}",
    }
    delivery = WebhookDelivery(
        dedupe_key=key,
        event_type=event_type,
        finding_id=finding.id,
        payload_json=json.dumps(payload, sort_keys=True),
    )
    db.add(delivery)
    db.flush()
    try:
        response = requests.post(
            f"{settings.webhook_url.rstrip('/')}/api/dependency-watch",
            json=payload,
            timeout=5,
        )
        delivery.response_status = response.status_code
        try:
            response_body = response.json()
        except ValueError:
            response_body = {"body": response.text[:1000]}
        delivery.response_json = json.dumps(response_body, sort_keys=True)
        delivery.success = response.ok and isinstance(response_body, dict) and response_body.get("ok") is True
        delivery.receiver_id = response_body.get("id") if isinstance(response_body, dict) else None
        if not delivery.success:
            delivery.error = "Receiver did not confirm delivery with {ok: true}."
    except requests.RequestException as exc:
        delivery.error = str(exc)
        delivery.success = False
    db.flush()
    return delivery


def receiver_check(db: Session, delivery: WebhookDelivery) -> dict:
    try:
        response = requests.get(f"{settings.webhook_url.rstrip('/')}/api/received", timeout=5)
        response.raise_for_status()
        received = response.json()
        matching = [item for item in received if item.get("body") == json.loads(delivery.payload_json)]
        result = {"delivery_id": delivery.id, "receiver_has_payload": bool(matching), "received_count": len(received)}
        if not matching:
            delivery.success = False
            delivery.error = "Receiver GET endpoint did not contain the delivered payload."
        db.commit()
        return result
    except (requests.RequestException, ValueError) as exc:
        return {"delivery_id": delivery.id, "receiver_has_payload": False, "error": str(exc)}
