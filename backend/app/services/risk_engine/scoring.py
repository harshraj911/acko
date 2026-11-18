SEVERITY_ORDER = {"LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def finding_priority(severity: str | None, tier: int, internet_facing: bool, dev_only: bool) -> str:
    score = SEVERITY_ORDER.get((severity or "").upper(), 1)
    score += 1 if tier == 1 else 0
    score += 1 if internet_facing else 0
    if dev_only:
        score -= 2
    if score >= 6:
        return "Critical"
    if score >= 4:
        return "High"
    if score >= 2:
        return "Medium"
    return "Low"
