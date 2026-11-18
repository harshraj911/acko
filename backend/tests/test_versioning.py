import pytest

from app.services.versioning.ranges import is_affected, normalize_package_name


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
