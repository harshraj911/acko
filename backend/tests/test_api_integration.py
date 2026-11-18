import json
import time
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.database.session import get_db
from app.api.routes import router
from app.models import (
    Dependency, DependencyRelationship, Finding, FindingObservation, ScanResult,
    ScanBatch, ScanSession, Service, VulnerabilityAdvisory, VulnerabilityAffectedRange,
    WebhookDelivery,
)


class Response:
    ok = True
    status_code = 200
    text = '{"ok":true,"id":42}'
    def json(self): return {"ok": True, "id": 42}


def test_public_api_scan_progress_analytics_graph_lifecycle_and_webhooks(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{(tmp_path / 'api-integration.db').as_posix()}",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr("app.services.webhooks.delivery.requests.post", lambda *a, **k: Response())
    monkeypatch.setattr("app.api.routes.requests.post", lambda *a, **k: Response())
    import app.services.scanner.jobs as jobs
    monkeypatch.setattr(jobs, "SessionLocal", Session)
    monkeypatch.setattr("app.api.routes.SessionLocal", Session)
    db = Session()

    service_dir = tmp_path / "service"
    service_dir.mkdir()
    package_json = service_dir / "package.json"
    package_lock = service_dir / "package-lock.json"
    package_json.write_text(json.dumps({"dependencies": {"x": "*"}}))

    def set_version(version):
        package_lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"x": "*"}}, "node_modules/x": {"version": version},
        }}))
    set_version("1.0.0")
    service = Service(name="api-integration-svc", owner="team", tier=1, internet_facing=True,
                      root_path=str(service_dir), ecosystem="npm")
    dependency = Dependency(ecosystem="npm", normalized_name="x", display_name="x")
    advisory = VulnerabilityAdvisory(id="DW-API-1", summary="integration finding", details="", source_severity="HIGH", raw_json="{}")
    db.add_all([service, dependency, advisory])
    db.flush()
    db.add(VulnerabilityAffectedRange(advisory_id=advisory.id, ecosystem="npm", package_name="x",
        normalized_name="x", range_type="SEMVER", events_json=json.dumps([{"introduced":"0"},{"fixed":"2.0.0"}])))
    db.commit()
    db.close()

    api_app = FastAPI()
    api_app.include_router(router, prefix="/api")
    api_app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"],
                           allow_methods=["*"], allow_headers=["*"], allow_credentials=True)

    def override_db():
        request_db = Session()
        try:
            yield request_db
        finally:
            request_db.close()
    api_app.dependency_overrides[get_db] = override_db
    monkeypatch.setattr("app.services.scanner.jobs.SessionLocal", Session)
    client = TestClient(api_app)
    try:
        service_response = client.get("/api/services", params={"search": "integration", "ecosystem": "npm"})
        assert service_response.status_code == 200
        assert service_response.json()["items"][0]["name"] == service.name

        accepted = client.post("/api/scans")
        assert accepted.status_code == 202
        scan_id = accepted.json()["scan_ids"][0]
        batch_id = accepted.json()["batch_id"]
        deadline = time.time() + 10
        progress = None
        batch_progress = None
        while time.time() < deadline:
            progress = client.get(f"/api/scans/{scan_id}/progress").json()
            batch_progress = client.get(f"/api/scan-batches/{batch_id}/progress").json()
            if batch_progress["status"] in {"completed", "failed"}:
                break
            time.sleep(.02)
        progress = client.get(f"/api/scans/{scan_id}/progress").json()
        db.expire_all()
        statuses = [(row.id, row.status, row.error) for row in db.scalars(select(ScanSession)).all()]
        assert progress and progress["status"] == "completed", {"scan": progress, "batch": batch_progress, "statuses": statuses}
        assert progress["packages_inspected"] == 1
        assert batch_progress["completed_services"] == 1
        sse_response = client.get(f"/api/scans/{scan_id}/events")
        assert sse_response.status_code == 200 and "completed" in sse_response.text
        assert client.get(f"/api/scans/{scan_id}/progress/stream").status_code == 200
        assert "overall_progress" in progress
        assert "file_being_processed" in progress
        assert "elapsed_duration" in progress

        scan_list = client.get("/api/scans", params={"service_id": service.id, "limit": 10}).json()
        assert scan_list["total"] >= 1
        finding_list = client.get("/api/findings", params={"search": advisory.id, "status": "open", "limit": 5}).json()
        assert finding_list["total"] == 1
        finding = finding_list["items"][0]

        db = Session()
        direct_count = db.scalar(select(func.count(Finding.id)).where(Finding.status != "resolved"))
        overview = client.get("/api/overview").json()
        analytics = client.get("/api/analytics").json()
        analytics_overview = client.get("/api/analytics/overview").json()
        assert overview["open_findings"] == direct_count
        assert analytics_overview["open_findings"] == direct_count
        assert analytics["total_packages_scanned"] == 1
        assert client.get("/api/analytics/vulnerabilities-by-severity").status_code == 200
        assert client.get("/api/analytics/vulnerabilities-by-service").status_code == 200
        assert client.get("/api/analytics/open-over-time").status_code == 200
        assert client.get("/api/analytics/resolved-over-time").status_code == 200

        graph = client.get(f"/api/services/{service.id}/graph").json()
        assert len(graph["nodes"]) == 2
        assert graph["nodes"][1]["vulnerable"] is True
        assert graph["vulnerable_chains"]

        global_graph = client.get("/api/graph").json()
        assert len(global_graph["nodes"]) >= 2

        unverified = client.get("/api/findings/unverified").json()
        assert "items" in unverified

        due = client.patch(f"/api/findings/{finding['id']}/due-date", json={
            "due_date": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        })
        assert due.status_code == 200
        assert len(client.get("/api/findings/overdue").json()) == 1
        history = client.get(f"/api/findings/{finding['id']}/history")
        assert history.status_code == 200

        rejected = client.patch(f"/api/findings/{finding['id']}/status", json={"status":"Resolved"})
        assert rejected.status_code == 409
        set_version("2.0.0")
        accepted_resolution = client.patch(f"/api/findings/{finding['id']}/status", json={"status":"Resolved"})
        assert accepted_resolution.status_code == 200

        deliveries = client.get("/api/webhooks/deliveries").json()
        assert deliveries["total"] >= 1
        assert all(row["success"] for row in deliveries["items"])
        assert client.get("/api/settings").status_code == 200
        test_hook = client.post("/api/webhooks/test").json()
        assert test_hook["success"] is True
        assert client.options("/api/services", headers={"Origin":"http://localhost:5173",
              "Access-Control-Request-Method":"GET"}).headers.get("access-control-allow-origin") == "http://localhost:5173"
    finally:
        api_app.dependency_overrides.clear()
        client.close()
        db.close()
        engine.dispose()


def test_periodic_overdue_check_notifies_once(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{(tmp_path / 'overdue-api.db').as_posix()}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    db = Session()
    service = Service(name="overdue-api", owner="team", tier=2, ecosystem="npm")
    dependency = Dependency(ecosystem="npm", normalized_name="x", display_name="x")
    advisory = VulnerabilityAdvisory(id="DW-OVERDUE", summary="overdue", details="", source_severity="HIGH", raw_json="{}")
    db.add_all([service, dependency, advisory])
    db.flush()
    from app.models import Finding
    finding = Finding(service_id=service.id, dependency_id=dependency.id, advisory_id=advisory.id,
                      instance_key="npm:x", first_scan_id=1, last_seen_scan_id=1, current_scan_result_id=1,
                      installed_version="1.0.0", status="open", priority="High",
                      due_date=datetime.now(timezone.utc) - timedelta(days=1))
    db.add(finding)
    db.commit()
    import app.services.overdue as overdue
    monkeypatch.setattr(overdue, "SessionLocal", Session)
    monkeypatch.setattr("app.services.webhooks.delivery.requests.post", lambda *a, **k: Response())
    assert overdue.check_overdue_once() == 1
    assert overdue.check_overdue_once() == 0
    assert db.query(WebhookDelivery).filter_by(event_type="finding.overdue").count() == 1
    db.close()
    engine.dispose()
