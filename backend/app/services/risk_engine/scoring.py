from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


# The point weights and priority bands are product heuristics, not CVSS values.
RISK_WEIGHTS = {
    "severity": {"LOW": 1, "MODERATE": 3, "MEDIUM": 3, "HIGH": 5, "CRITICAL": 8},
    "service_tier": {1: 3, 2: 2, 3: 0},
    "internet_exposure": 2,
    "fixed_version_available": 0,
    "no_fixed_version": 1,
    "complexity": {"patch": 0, "minor": 1, "major": 2, "unknown": 1},
    "dev_only_adjustment": -2,
}
PRIORITY_BANDS = ((10, "Critical"), (7, "High"), (3, "Medium"), (0, "Low"))
SEVERITY_PRIORITY = {"LOW": "Low", "MODERATE": "Medium", "MEDIUM": "Medium", "HIGH": "High", "CRITICAL": "Critical"}
DUE_DATE_DAYS = {"Critical": 1, "High": 7, "Medium": 30, "Low": 90}


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    priority: str
    breakdown: list[dict]


def assess_risk(
    severity: str | None,
    tier: int,
    internet_facing: bool,
    fixed_version_available: bool,
    upgrade_complexity: str = "unknown",
    dev_only: bool = False,
) -> RiskAssessment:
    source_severity = (severity or "").upper()
    severity_points = RISK_WEIGHTS["severity"].get(source_severity, 1)
    tier_points = RISK_WEIGHTS["service_tier"].get(tier, 0)
    exposure_points = RISK_WEIGHTS["internet_exposure"] if internet_facing else 0
    fix_points = (
        RISK_WEIGHTS["fixed_version_available"] if fixed_version_available
        else RISK_WEIGHTS["no_fixed_version"]
    )
    complexity_key = upgrade_complexity if upgrade_complexity in RISK_WEIGHTS["complexity"] else "unknown"
    complexity_points = RISK_WEIGHTS["complexity"][complexity_key]
    dev_points = RISK_WEIGHTS["dev_only_adjustment"] if dev_only else 0

    breakdown = [
        {"factor": "Advisory severity", "source_value": severity or "Unspecified", "contribution": severity_points,
         "explanation": f"Feed severity {severity or 'unspecified'} contributes {severity_points} point{'s' if severity_points != 1 else ''}."},
        {"factor": "Service criticality", "source_value": f"Tier {tier}", "contribution": tier_points,
         "explanation": f"Tier {tier} service criticality contributes {tier_points} points."},
        {"factor": "Internet exposure", "source_value": "Internet-facing" if internet_facing else "Internal",
         "contribution": exposure_points,
         "explanation": "Internet exposure adds 2 points." if internet_facing else "Internal-only reachability adds 0 points."},
        {"factor": "Fixed version", "source_value": "Available" if fixed_version_available else "Not published",
         "contribution": fix_points,
         "explanation": "A published fix adds 0 urgency points." if fixed_version_available else "No published fixed version adds 1 point because remediation is constrained."},
        {"factor": "Upgrade complexity", "source_value": complexity_key, "contribution": complexity_points,
         "explanation": f"A {complexity_key} upgrade contributes {complexity_points} point{'s' if complexity_points != 1 else ''}."},
        {"factor": "Dependency scope", "source_value": "Development-only" if dev_only else "Runtime",
         "contribution": dev_points,
         "explanation": "Development-only scope reduces the score by 2 points compared with the same runtime issue." if dev_only else "Runtime dependency receives no scope reduction."},
    ]
    raw_score = max(0, sum(item["contribution"] for item in breakdown))
    priority = next(label for minimum, label in PRIORITY_BANDS if raw_score >= minimum)
    severity_priority = SEVERITY_PRIORITY.get(source_severity, "Low")
    band_order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    cap_priority = {
        "Low": "Medium", "Medium": "High", "High": "Critical", "Critical": "Critical",
    }[severity_priority]
    if band_order[priority] > band_order[cap_priority]:
        band_max = {"Low": 2, "Medium": 6, "High": 9, "Critical": raw_score}
        capped_score = min(raw_score, band_max[cap_priority])
        breakdown.append({
            "factor": "Advisory severity cap",
            "source_value": f"{source_severity or 'LOW'} -> {cap_priority}",
            "contribution": capped_score - raw_score,
            "explanation": f"Raw priority {priority} (score {raw_score}) was capped at {cap_priority} (score {capped_score}), at most one band above advisory severity {source_severity or 'LOW'}.",
            "capped": True,
        })
        return RiskAssessment(score=capped_score, priority=cap_priority, breakdown=breakdown)
    return RiskAssessment(score=raw_score, priority=priority, breakdown=breakdown)


def finding_priority(severity: str | None, tier: int, internet_facing: bool, dev_only: bool) -> str:
    return assess_risk(severity, tier, internet_facing, True, "unknown", dev_only).priority


def default_due_date(priority: str, now: datetime | None = None) -> datetime:
    return (now or datetime.now(timezone.utc)) + timedelta(days=DUE_DATE_DAYS[priority])
