import pytest

from app.services.versioning.ranges import is_affected, normalize_package_name
from app.services.risk_engine.scoring import assess_risk, default_due_date
from app.services.remediation.recommendations import fixed_for_affected_range, upgrade_complexity


@pytest.mark.parametrize(("version", "expected"), [
    ("0.0.1", True),
    ("1.9.9", True),
    ("2.0.0-rc.1", True),
    ("2.0.0", False),
    ("3.0.0", False),
])
def test_npm_range_boundaries_and_prerelease(version, expected):
    ranges = [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]
    assert is_affected("npm", version, ranges) is expected


def test_multiple_disjoint_ranges_and_open_ended_range():
    ranges = [
        {"events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]},
        {"events": [{"introduced": "2.0.0"}]},
    ]
    assert is_affected("npm", "1.1.9", ranges)
    assert not is_affected("npm", "1.2.0", ranges)
    assert is_affected("npm", "99.0.0", ranges)


@pytest.mark.parametrize(("version", "expected"), [
    ("5.3.0rc1", True),
    ("5.3.0", True),
    ("5.4.0", False),
    ("5.3.0+local.1", True),
])
def test_pep440_versions(version, expected):
    ranges = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]
    assert is_affected("PyPI", version, ranges) is expected


def test_unusual_python_release_and_name_normalization():
    ranges = [{"events": [{"introduced": "1.0.dev1"}, {"fixed": "1.0.post2"}]}]
    assert is_affected("PyPI", "1.0.post1", ranges)
    assert normalize_package_name("PyPI", "python_multipart") == "python-multipart"
    assert normalize_package_name("PyPI", "Python.Multipart") == "python-multipart"


def test_invalid_version_is_not_assumed_vulnerable():
    assert not is_affected("npm", "not-a-version", [{"events": [{"introduced": "0"}]}])


def test_risk_score_is_explainable_and_dev_only_reduces_score():
    runtime = assess_risk("CRITICAL", 1, True, True, "major", False)
    development = assess_risk("CRITICAL", 1, True, True, "major", True)
    assert runtime.priority == "Critical"
    assert runtime.score == development.score + 2
    assert development.breakdown[-1]["contribution"] == -2
    assert "not CVSS" not in " ".join(row["explanation"] for row in runtime.breakdown).lower()
    assert default_due_date("Critical").date() <= default_due_date("High").date()


@pytest.mark.parametrize(("severity", "tier", "exposure", "complexity", "dev", "cap"), [
    ("LOW", 1, True, "major", False, "Medium"),
    ("MODERATE", 1, True, "major", False, "High"),
    ("HIGH", 1, True, "major", False, "Critical"),
    ("CRITICAL", 3, False, "patch", True, "Critical"),
])
def test_priority_never_exceeds_one_band_over_source_severity(severity, tier, exposure, complexity, dev, cap):
    assessment = assess_risk(severity, tier, exposure, False, complexity, dev)
    order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    assert order[assessment.priority] <= order[cap]
    if severity in {"LOW", "MODERATE"}:
        assert any(item["factor"] == "Advisory severity cap" for item in assessment.breakdown)
        cap_entry = next(item for item in assessment.breakdown if item["factor"] == "Advisory severity cap")
        assert cap_entry.get("capped") is True
        assert cap_entry["contribution"] < 0


SEVERITY_TO_PRIORITY = {"LOW": "Low", "MODERATE": "Medium", "HIGH": "High", "CRITICAL": "Critical"}


@pytest.mark.parametrize(("ecosystem", "installed", "events", "expected", "complexity"), [
    ("npm", "6.7.0", [{"introduced": "6.0.0"}, {"fixed": "6.7.3"}], "6.7.3", "patch"),
    ("PyPI", "4.1.0", [{"introduced": "4.1"}, {"fixed": "4.1.2"}], "4.1.2", "patch"),
    ("npm", "8.5.1", [{"introduced": "0"}, {"fixed": "9.0.0"}], "9.0.0", "major"),
])
def test_fixed_version_is_from_the_affected_range(ecosystem, installed, events, expected, complexity):
    assert fixed_for_affected_range(ecosystem, installed, events) == expected
    assert upgrade_complexity(ecosystem, installed, expected) == complexity


def test_no_fixed_event_does_not_invent_recommendation():
    assert fixed_for_affected_range("npm", "1.19.0", [{"introduced": "0"}]) is None
