import json

from app.models import (
    Finding, ScanResult, ScanSession, Service, VulnerabilityAdvisory,
    VulnerabilityAffectedRange,
)
from app.services.scanner.parser import scan_manifests
from app.services.scanner.runner import scan_service


KIT = __import__("app.core.config", fromlist=["DEFAULT_KIT_PATH"]).DEFAULT_KIT_PATH


def test_real_npm_lock_tracks_nested_instances_and_transitives():
    packages = scan_manifests(KIT / "services" / "notifications-svc")
    qs = [item for item in packages if item.name == "qs"]
    assert {item.version for item in qs} == {"6.11.0", "6.5.2"}
    assert all(not item.direct for item in qs)
    assert len({item.instance_key for item in qs}) == 2
    assert all(item.parents for item in qs)


def test_python_locks_parse_direct_and_multiline_via_relationships():
    packages = scan_manifests(KIT / "services" / "policy-svc")
    by_name = {item.normalized_name: item for item in packages}
    assert by_name["flask"].direct
    assert by_name["requests"].direct
    assert by_name["werkzeug"].parents == ["flask"]
    assert by_name["markupsafe"].parents == ["jinja2", "werkzeug"]


def test_dev_requirements_are_flagged_separately():
    packages = scan_manifests(KIT / "services" / "kyc-svc")
    pytest_package = next(item for item in packages if item.normalized_name == "pytest")
    assert pytest_package.dev_only
    assert pytest_package.direct
    assert pytest_package.version == "6.2.4"


def test_missing_python_lock_keeps_specifier_unresolved():
    packages = scan_manifests(KIT / "services" / "docs-gen-svc")
    jinja = next(item for item in packages if item.normalized_name == "jinja2")
    assert jinja.version is None
    assert not jinja.resolved
    assert jinja.specifier == "<3.1,>=2.10"


def test_npm_transitive_links_follow_package_lock_dependencies(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"root": "1"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"root": "1"}},
            "node_modules/root": {"version": "1.0.0", "dependencies": {"leaf": "1"}},
            "node_modules/leaf": {"version": "1.1.0"},
        },
    }))
    packages = scan_manifests(tmp_path)
    root = next(item for item in packages if item.name == "root")
    leaf = next(item for item in packages if item.name == "leaf")
    assert root.direct and not leaf.direct
    assert leaf.parents == ["node_modules/root"]


def test_scans_preserve_snapshots_and_do_not_duplicate_findings(tmp_path, db_session):
    service_dir = tmp_path / "svc"
    service_dir.mkdir()
    (service_dir / "package.json").write_text(json.dumps({"dependencies": {"x": "1"}}))
    (service_dir / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"x": "1"}},
            "node_modules/x": {"version": "1.0.0"},
        },
    }))
    service = Service(
        name="snapshot-test", owner="test", tier=1, internet_facing=True,
        root_path=str(service_dir), ecosystem="npm",
    )
    advisory = VulnerabilityAdvisory(
        id="DW-SNAPSHOT", summary="test", details="", source_severity="HIGH", raw_json="{}",
    )
    db_session.add_all([service, advisory])
    db_session.flush()
    db_session.add(VulnerabilityAffectedRange(
        advisory_id=advisory.id, ecosystem="npm", package_name="x", normalized_name="x",
        range_type="SEMVER", events_json=json.dumps([{"introduced": "0"}, {"fixed": "2.0.0"}]),
    ))
    db_session.commit()

    first = scan_service(db_session, service)
    second = scan_service(db_session, service)
    assert first.id != second.id
    assert db_session.query(ScanSession).count() == 2
    assert db_session.query(ScanResult).count() == 2
    assert db_session.query(Finding).count() == 1
    finding = db_session.query(Finding).one()
    assert finding.first_scan_id == first.id
    assert finding.last_seen_scan_id == second.id

    (service_dir / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"x": "1"}},
            "node_modules/x": {"version": "2.0.0"},
        },
    }))
    third = scan_service(db_session, service)
    assert db_session.query(ScanResult).count() == 3
    assert finding.status == "resolved"
    assert finding.resolution_reason == "scan_clear"
    assert third.id == finding.last_seen_scan_id or finding.status == "resolved"
