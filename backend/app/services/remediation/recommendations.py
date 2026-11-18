import json

from app.models import Dependency, DependencyRelationship, ScanResult, VulnerabilityAffectedRange
from app.services.versioning.ranges import _compare, _parse, is_affected


def fixed_for_affected_range(ecosystem: str, version: str, events: list[dict]) -> str | None:
    in_range = False
    for event in events:
        if "introduced" in event:
            introduced = event["introduced"]
            in_range = introduced == "0" or _compare(ecosystem, version, introduced) >= 0
        elif "fixed" in event:
            fixed = event["fixed"]
            if in_range and _compare(ecosystem, version, fixed) < 0:
                return fixed
            in_range = False
    return None


def upgrade_complexity(ecosystem: str, installed: str, fixed: str | None) -> str:
    if not fixed:
        return "unknown"
    current = _parse(ecosystem, installed)
    target = _parse(ecosystem, fixed)
    if ecosystem.lower() == "npm":
        current_release = (current.major, current.minor, current.patch)
        target_release = (target.major, target.minor, target.patch)
    else:
        current_release = current.release
        target_release = target.release
    padded_current = current_release + (0,) * max(0, 3 - len(current_release))
    padded_target = target_release + (0,) * max(0, 3 - len(target_release))
    if padded_current[0] != padded_target[0]:
        return "major"
    if padded_current[1] != padded_target[1]:
        return "minor"
    return "patch"


def _fixed_for_range(ecosystem: str, version: str, events: list[dict]) -> str | None:
    in_range = False
    for event in events:
        if "introduced" in event:
            introduced = event["introduced"]
            in_range = introduced == "0" or _compare(ecosystem, version, introduced) >= 0
        elif "fixed" in event:
            fixed = event["fixed"]
            if in_range and _compare(ecosystem, version, fixed) < 0:
                return fixed
            in_range = False
    return None


def recommendation_for(db, finding, service, dependency, advisory) -> dict:
    ranges = db.query(VulnerabilityAffectedRange).filter_by(advisory_id=advisory.id).all()
    matching_ranges = []
    for affected in ranges:
        if (affected.ecosystem.lower(), affected.normalized_name) != (
            dependency.ecosystem.lower(), dependency.normalized_name,
        ):
            continue
        events = json.loads(affected.events_json)
        if is_affected(dependency.ecosystem, finding.installed_version, [{"events": events}]):
            matching_ranges.append((affected, events))

    fixed_versions = [
        fixed for affected, events in matching_ranges
        if (fixed := fixed_for_affected_range(affected.ecosystem, finding.installed_version, events))
    ]
    fixed = min(fixed_versions, key=lambda value: _parse(dependency.ecosystem, value)) if fixed_versions else None
    scan_result = db.get(ScanResult, finding.current_scan_result_id)
    edge = db.query(DependencyRelationship).filter_by(
        scan_session_id=scan_result.scan_session_id if scan_result else None,
        child_result_id=scan_result.id if scan_result else None,
    ).filter(DependencyRelationship.parent_result_id.is_not(None)).first()
    parent_name = None
    if edge:
        parent_result = db.get(ScanResult, edge.parent_result_id)
        if parent_result:
            parent_dependency = db.get(Dependency, parent_result.dependency_id)
            parent_name = parent_dependency.display_name if parent_dependency else None
    if edge is None and scan_result:
        dep_path = scan_result.package_path
        if dependency.ecosystem.lower() == "npm" and dep_path.startswith("node_modules/"):
            parent_paths = []
            remaining = dep_path
            while "/node_modules/" in remaining:
                prefix, suffix = remaining.rsplit("/node_modules/", 1)
                parent_paths.append(f"{prefix}/node_modules/{suffix.split('/node_modules/', 1)[0]}")
                remaining = prefix
            for parent_path in parent_paths:
                parent_result = db.query(ScanResult).filter_by(
                    scan_session_id=scan_result.scan_session_id, package_path=parent_path,
                ).first()
                if parent_result:
                    parent_dependency = db.get(Dependency, parent_result.dependency_id)
                    parent_name = parent_dependency.display_name if parent_dependency else None
                    break
    direct = bool(scan_result and scan_result.direct)
    if direct:
        dep_type = "Direct"
        note = "Update this dependency in the service manifest."
    elif parent_name:
        dep_type = "Transitive"
        note = f"Update the parent package {parent_name}; it introduces this transitive package."
    else:
        dep_type = "Transitive"
        note = "This is transitive, but the available lockfile relationships do not identify a parent package."
    if not fixed:
        return {
            "installed_version": finding.installed_version,
            "fixed_version": None,
            "fix_available": False,
            "upgrade_complexity": "unknown",
            "recommendation": "No fix is published in the feed. Monitor the advisory and evaluate a mitigation that fits the service.",
            "dependency_type": "Development-only" if finding.dev_only else dep_type,
            "parent_package": parent_name,
            "chain_note": note + " No fixed version is specified by the matching advisory range.",
        }

    complexity = upgrade_complexity(dependency.ecosystem, finding.installed_version, fixed)
    return {
        "installed_version": finding.installed_version,
        "fixed_version": fixed,
        "fix_available": True,
        "upgrade_complexity": complexity,
        "recommendation": f"Upgrade to the verified fixed version {fixed}.",
        "dependency_type": dep_type,
        "parent_package": parent_name,
        "chain_note": note,
    }
