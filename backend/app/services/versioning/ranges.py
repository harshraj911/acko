import re
from functools import total_ordering

import semver
from packaging.version import InvalidVersion, Version


def normalize_package_name(ecosystem: str, name: str) -> str:
    if ecosystem.lower() in {"pypi", "python"}:
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def _parse(ecosystem: str, value: str):
    if ecosystem.lower() == "npm":
        return semver.Version.parse(value.removeprefix("v"))
    return Version(value)


def _compare(ecosystem: str, left: str, right: str) -> int:
    a = _parse(ecosystem, left)
    b = _parse(ecosystem, right)
    return (a > b) - (a < b)


def is_affected(ecosystem: str, version: str, ranges: list[dict]) -> bool:
    """Evaluate ordered OSV introduced/fixed event pairs, with fixed exclusive."""
    try:
        _parse(ecosystem, version)
    except (ValueError, InvalidVersion):
        return False

    for range_entry in ranges:
        events = range_entry.get("events", [])
        in_range = False
        for event in events:
            if "introduced" in event:
                introduced = event["introduced"]
                try:
                    lower_ok = introduced == "0" or _compare(ecosystem, version, introduced) >= 0
                except (ValueError, InvalidVersion):
                    lower_ok = False
                in_range = lower_ok
            elif "fixed" in event:
                fixed = event["fixed"]
                try:
                    if in_range and _compare(ecosystem, version, fixed) < 0:
                        return True
                except (ValueError, InvalidVersion):
                    pass
                in_range = False
            elif "last_affected" in event and in_range:
                try:
                    if _compare(ecosystem, version, event["last_affected"]) <= 0:
                        return True
                except (ValueError, InvalidVersion):
                    pass
                in_range = False
        if in_range:
            return True
    return False
