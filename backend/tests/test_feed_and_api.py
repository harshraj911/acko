import json
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.database.session import get_db
from app.main import app
from app.models import Dependency, Finding, ScanResult, ScanSession, Service, VulnerabilityAdvisory
from app.services.scanner.runner import scan_service
from app.services.vulnerability.importer import import_feed


class MockResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


def test_repeated_advisory_import_is_idempotent(monkeypatch, db_session):
    payload = {"feed": 1, "advisories": [{
        "id": "DW-TEST-1", "summary": "test", "details": "details",
        "affected": [{"package": {"ecosystem": "npm", "name": "x"}, "ranges": [
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}
        ]}],
    }]}
    monkeypatch.setattr("app.services.vulnerability.importer.requests.get", lambda *a, **k: MockResponse(payload))
    first = import_feed(db_session, "http://feed")
    second = import_feed(db_session, "http://feed")
    assert first["imported"] == 1
    assert second["unchanged"] == 1
    assert db_session.query(VulnerabilityAdvisory).count() == 1
    assert db_session.query(VulnerabilityAdvisory).filter_by(id="DW-TEST-1").one()


def test_feed_withdrawal_resolves_active_finding(monkeypatch, db_session):
    db_session.add(Service(name="demo", owner="team", tier=1, internet_facing=True, ecosystem="npm"))
    db_session.flush()
    from app.models import Dependency, Finding
    dependency = Dependency(ecosystem="npm", normalized_name="x", display_name="x")
    advisory = VulnerabilityAdvisory(id="DW-TEST-2", summary="test", details="", raw_json="{}")
    db_session.add_all([dependency, advisory])
    db_session.flush()
    service = db_session.query(Service).filter_by(name="demo").one()
    scan = ScanSession(service_id=service.id, status="completed", package_count=1)
    db_session.add(scan)
    db_session.flush()
    result = ScanResult(
        scan_session_id=scan.id, dependency_id=dependency.id, instance_key="npm:node_modules/x",
        package_path="node_modules/x", version="1.0.0", direct=True, dev_only=False,
        resolved=True, verification_state="verified", manifest_file="package-lock.json",
    )
    db_session.add(result)
    db_session.flush()
    db_session.add(Finding(
        service_id=service.id, dependency_id=dependency.id, advisory_id=advisory.id,
        instance_key="npm:node_modules/x", first_scan_id=scan.id, last_seen_scan_id=scan.id,
        current_scan_result_id=result.id, installed_version="1.0.0", source_severity="HIGH",
        status="open", first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc),
    ))
    db_session.commit()
    payload = {"feed": 1, "advisories": [{
        "id": "DW-TEST-2", "summary": "active", "details": "test",
        "database_specific": {"severity": "MODERATE"},
        "affected": [{"package": {"ecosystem": "npm", "name": "x"}, "ranges": [
            {"type": "SEMVER", "events": [{"introduced": "0"}]}
        ]}],
    }]}
    monkeypatch.setattr("app.services.vulnerability.importer.requests.get", lambda *a, **k: MockResponse(payload))
    import_feed(db_session, "http://feed")
    payload["feed"] = 2
    payload["advisories"][0]["summary"] = "withdrawn record retained"
    payload["advisories"][0]["withdrawn"] = "2026-11-12T00:00:00Z"
    import_feed(db_session, "http://feed")
    finding = db_session.query(Finding).one()
    assert finding.status == "resolved"
    assert finding.resolution_reason == "withdrawn"
    advisory = db_session.get(VulnerabilityAdvisory, "DW-TEST-2")
    assert advisory.withdrawn == "2026-11-12T00:00:00Z"
    assert advisory.source_severity == "MODERATE"
    assert db_session.query(VulnerabilityAdvisory).count() == 1


def test_service_api_lists_registered_services(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{(tmp_path / 'api.db').as_posix()}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    db = Session()
    db.add(Service(name="api-service", owner="API", tier=2, ecosystem="npm"))
    db.commit()

    def override_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as client:
            response = client.get("/api/services?ecosystem=npm&search=api")
            assert response.status_code == 200
            assert [row["name"] for row in response.json()] == ["api-service"]
    finally:
        app.dependency_overrides.clear()
        db.close()
        engine.dispose()
