import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.database.session import get_db
from app.main import app
from app.models import (
    ActivityLog, Dependency, Finding, FindingAssignment, FindingEvent, ScanChange,
    ScanResult, ScanSession, Service, VulnerabilityAdvisory, VulnerabilityAffectedRange,
    WebhookDelivery,
)
from app.services.remediation.recommendations import recommendation_for
from app.services.scanner.runner import scan_service
from app.services.webhooks.delivery import deliver_webhook


class MockResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self.ok = 200 <= status_code < 400
        self.payload = payload if payload is not None else {"ok": True, "id": 5}
        self.text = json.dumps(self.payload)

    def json(self):
        return self.payload

    def raise_for_status(self):
        if not self.ok:
            raise RuntimeError("HTTP error")


def make_service_with_finding(db, tmp_path, version="1.0.0", fixed="2.0.0", advisory_id="DW-WF-1"):
    service_dir = tmp_path / "workflow-service"
    service_dir.mkdir(exist_ok=True)
    (service_dir / "package.json").write_text(json.dumps({"dependencies": {"x": "*"}}))
    lock_path = service_dir / "package-lock.json"

    def set_version(value):
        lock_path.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {"": {"dependencies": {"x": "*"}}, "node_modules/x": {"version": value}},
        }))

    set_version(version)
    service = Service(name="workflow", owner="service-team", tier=1, internet_facing=True,
                      root_path=str(service_dir), ecosystem="npm")
    dependency = Dependency(ecosystem="npm", normalized_name="x", display_name="x")
    advisory = VulnerabilityAdvisory(id=advisory_id, summary="test advisory", details="", published=None,
                                    modified=None, withdrawn=None, source_severity="HIGH", raw_json="{}")
    db.add_all([service, dependency, advisory])
    db.flush()
    scan = ScanSession(service_id=service.id, status="completed", package_count=1)
    db.add(scan)
    db.flush()
    result = ScanResult(
        scan_session_id=scan.id, dependency_id=dependency.id, instance_key="node_modules/x",
        package_path="node_modules/x", version=version, direct=True, dev_only=False,
        resolved=True, verification_state="verified", manifest_file="package-lock.json",
    )
    db.add(result)
    db.flush()
    db.add(VulnerabilityAffectedRange(
        advisory_id=advisory_id, ecosystem="npm", package_name="x", normalized_name="x",
        range_type="SEMVER", events_json=json.dumps([{"introduced": "0"}, {"fixed": fixed}]),
    ))
    db.commit()
    return service, dependency, advisory, set_version


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{(tmp_path / 'workflow-api.db').as_posix()}")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, expire_on_commit=False)()

    class LocalWebhookResponse:
        ok = True
        status_code = 200
        text = '{"ok": true, "id": 1}'
        def json(self): return {"ok": True, "id": 1}

    monkeypatch.setattr("app.services.webhooks.delivery.requests.post", lambda *a, **k: LocalWebhookResponse())
    import app.services.scanner.jobs as scan_jobs
    monkeypatch.setattr(scan_jobs, "SessionLocal", lambda: Session())

    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app)
    yield client, db
    app.dependency_overrides.clear()
    db.close()
    engine.dispose()


@pytest.mark.parametrize(("package", "installed", "expected_fixed", "complexity"), [
    ("qs", "6.7.0", "6.7.3", "patch"),
    ("django", "4.1.0", "4.1.2", "patch"),
    ("jsonwebtoken", "8.5.1", "9.0.0", "major"),
])
def test_kit_advisory_fixed_recommendations(package, installed, expected_fixed, complexity, db_session):
    from app.core.config import DEFAULT_KIT_PATH
    from app.services.vulnerability.importer import import_feed
    import requests

    payload = json.loads((DEFAULT_KIT_PATH / "feed-server" / "feeds" / "feed-1" / {
        "qs": "DW-2026-0001.json", "django": "DW-2026-0008.json", "jsonwebtoken": "DW-2026-0002.json",
    }[package]).read_text(encoding="utf-8"))

    class FeedResponse:
        def raise_for_status(self): pass
        def json(self): return {"feed": 1, "advisories": [payload]}

    from app.services.vulnerability import importer
    old_get = importer.requests.get
    importer.requests.get = lambda *a, **k: FeedResponse()
    try:
        import_feed(db_session, "http://unused")
    finally:
        importer.requests.get = old_get
    from app.models import Finding
    service = Service(name=f"svc-{package}", owner="team", tier=2, ecosystem="npm" if package != "django" else "PyPI")
    dep = Dependency(ecosystem=service.ecosystem, normalized_name=package.lower(), display_name=package)
    db_session.add_all([service, dep])
    db_session.flush()
    advisory = db_session.get(VulnerabilityAdvisory, payload["id"])
    scan = ScanSession(service_id=service.id, status="completed", package_count=1)
    db_session.add(scan)
    db_session.flush()
    result = ScanResult(scan_session_id=scan.id, dependency_id=dep.id, instance_key=f"{service.ecosystem}:{package}",
                        package_path=package, version=installed, direct=True, dev_only=False,
                        resolved=True, verification_state="verified", manifest_file="test")
    db_session.add(result)
    db_session.flush()
    finding = Finding(
        service_id=service.id, dependency_id=dep.id, advisory_id=advisory.id,
        instance_key=result.instance_key, first_scan_id=scan.id, last_seen_scan_id=scan.id,
        current_scan_result_id=result.id, installed_version=installed, source_severity=advisory.source_severity,
        priority="High", status="open",
    )
    db_session.add(finding)
    db_session.commit()
    recommendation = recommendation_for(db_session, finding, service, dep, advisory)
    assert recommendation["fixed_version"] == expected_fixed
    assert recommendation["upgrade_complexity"] == complexity


def test_body_parser_has_no_published_fix_recommendation(db_session):
    from app.core.config import DEFAULT_KIT_PATH
    from app.services.vulnerability import importer
    payload = json.loads((DEFAULT_KIT_PATH / "feed-server" / "feeds" / "feed-1" / "DW-2026-0014.json").read_text())

    class FeedResponse:
        def raise_for_status(self): pass
        def json(self): return {"feed": 1, "advisories": [payload]}
    original = importer.requests.get
    importer.requests.get = lambda *a, **k: FeedResponse()
    try:
        importer.import_feed(db_session, "http://unused")
    finally:
        importer.requests.get = original
    service = Service(name="body-parser-service", owner="team", tier=3, ecosystem="npm")
    dep = Dependency(ecosystem="npm", normalized_name="body-parser", display_name="body-parser")
    db_session.add_all([service, dep])
    db_session.flush()
    advisory = db_session.get(VulnerabilityAdvisory, "DW-2026-0014")
    scan = ScanSession(service_id=service.id, status="completed", package_count=1)
    db_session.add(scan)
    db_session.flush()
    result = ScanResult(scan_session_id=scan.id, dependency_id=dep.id,
                        instance_key="npm:node_modules/body-parser", package_path="node_modules/body-parser",
                        version="1.19.0", direct=True, dev_only=False, resolved=True,
                        verification_state="verified", manifest_file="test")
    db_session.add(result)
    db_session.flush()
    finding = Finding(service_id=service.id, dependency_id=dep.id, advisory_id=advisory.id,
                      instance_key=result.instance_key, first_scan_id=scan.id, last_seen_scan_id=scan.id,
                      current_scan_result_id=result.id, installed_version="1.19.0", source_severity="LOW", status="open")
    db_session.add(finding)
    db_session.commit()
    recommendation = recommendation_for(db_session, finding, service, dep, advisory)
    assert recommendation["fixed_version"] is None
    assert "No fix is published in the feed" in recommendation["recommendation"]


def test_finding_assign_status_history_overdue_and_verified_resolution(api_client, tmp_path):
    client, db = api_client
    service, _dep, _advisory, change_version = make_service_with_finding(db, tmp_path)
    scan = scan_service(db, service)
    finding = db.query(Finding).one()
    assert finding.assigned_owner == "service-team"
    assert finding.due_date is not None

    assigned = client.patch(f"/api/findings/{finding.id}/assignment", json={"owner": "alice", "actor": "reviewer"})
    assert assigned.status_code == 200 and assigned.json()["owner"] == "alice"
    status = client.patch(f"/api/findings/{finding.id}/status", json={"status": "In Progress", "actor": "alice"})
    assert status.status_code == 200
    note = client.post(f"/api/findings/{finding.id}/notes", json={"note": "upgrade scheduled", "actor": "alice"})
    assert note.status_code == 200
    due = client.patch(f"/api/findings/{finding.id}/due-date", json={
        "due_date": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(), "actor": "alice",
    })
    assert due.status_code == 200
    overdue = client.get("/api/findings/overdue")
    assert overdue.status_code == 200 and len(overdue.json()) == 1

    rejected = client.patch(f"/api/findings/{finding.id}/status", json={"status": "Resolved", "actor": "alice"})
    assert rejected.status_code == 409
    change_version("2.0.0")
    accepted = client.patch(f"/api/findings/{finding.id}/status", json={"status": "Resolved", "actor": "alice"})
    assert accepted.status_code == 200
    assert accepted.json()["verification_scan_id"] is not None
    current = db.get(Finding, finding.id)
    assert current.resolution_info and "verification scan" in current.resolution_info
    history = client.get(f"/api/findings/{finding.id}/history").json()
    assert {event["event_type"] for event in history} >= {"created", "assigned", "status_changed", "note_added", "resolved"}

    change_version("1.0.0")
    scan_service(db, service)
    assert db.get(Finding, finding.id).status == "open"
    assert any(event.event_type == "reappeared" for event in db.query(FindingEvent).filter_by(finding_id=finding.id))


def test_scan_changes_capture_versions_and_vulnerability_transitions(api_client, tmp_path):
    _client, db = api_client
    service, _dep, _advisory, change_version = make_service_with_finding(db, tmp_path, version="2.0.0")
    first = scan_service(db, service)
    change_version("1.0.0")
    second = scan_service(db, service)
    changes = db.query(ScanChange).filter_by(scan_session_id=second.id).all()
    assert any(change.change_type == "version_changed" for change in changes)
    assert any(change.change_type == "vulnerability_new" for change in changes)
    change_version("2.0.0")
    third = scan_service(db, service)
    assert any(change.change_type == "vulnerability_resolved" for change in db.query(ScanChange).filter_by(scan_session_id=third.id))
    change_version("1.0.0")
    fourth = scan_service(db, service)
    assert any(change.change_type == "vulnerability_reappeared" for change in db.query(ScanChange).filter_by(scan_session_id=fourth.id))


def test_webhook_delivery_dedupes_and_records_failure(api_client, tmp_path, monkeypatch):
    _client, db = api_client
    service, dependency, advisory, _ = make_service_with_finding(db, tmp_path)
    monkeypatch.setattr("app.services.webhooks.delivery.requests.post", lambda *a, **k: MockResponse(200, {"ok": True, "id": 1}))
    scan = scan_service(db, service)
    initial_high_count = db.query(WebhookDelivery).filter_by(event_type="finding.high_priority").count()
    scan_service(db, service)
    assert db.query(WebhookDelivery).filter_by(event_type="finding.high_priority").count() == initial_high_count
    finding = db.query(Finding).one()
    monkeypatch.setattr("app.services.webhooks.delivery.requests.post", lambda *a, **k: MockResponse(200, {"ok": True, "id": 1}))
    first = deliver_webhook(db, "test.event", finding, service, dependency, advisory)
    second = deliver_webhook(db, "test.event", finding, service, dependency, advisory)
    assert first.id == second.id
    assert first.success and first.receiver_id == 1
    assert db.query(WebhookDelivery).filter_by(event_type="test.event").count() == 1

    db.delete(first)
    db.flush()
    monkeypatch.setattr("app.services.webhooks.delivery.requests.post", lambda *a, **k: (_ for _ in ()).throw(__import__("requests").ConnectionError("offline")))
    failed = deliver_webhook(db, "offline.event", finding, service, dependency, advisory)
    assert not failed.success
    assert "offline" in failed.error


def test_activity_filters_by_event_service_and_dates(api_client, tmp_path):
    client, db = api_client
    service, _dep, _advisory, _ = make_service_with_finding(db, tmp_path)
    scan_service(db, service)
    response = client.get("/api/activity", params={"event_type": "scan.completed", "service_id": service.id})
    assert response.status_code == 200
    assert response.json()["items"]
    assert all(event["service_id"] == service.id for event in response.json()["items"])
