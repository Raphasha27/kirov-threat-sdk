from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kirov_threat_sdk.models import Finding


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


_SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.0,
}

_RISK_THRESHOLDS = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (1.0, Severity.LOW),
]


def risk_score_to_level(score: float) -> Severity:
    for threshold, level in _RISK_THRESHOLDS:
        if score >= threshold:
            return level
    return Severity.INFO


def calculate_risk_score(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    total = sum(_SEVERITY_WEIGHTS.get(f.severity, 0.0) for f in findings)
    return round(total / len(findings), 2)
