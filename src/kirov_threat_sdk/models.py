from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel

from kirov_threat_sdk.severity import Severity


class ThreatStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Threat(BaseModel):
    id: int
    source_ip: str
    event_type: str
    severity: Severity
    title: str
    description: str
    raw_log: dict
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    risk_score: float
    status: ThreatStatus = ThreatStatus.OPEN
    detected_at: datetime
    ai_classification: Optional[str] = None


class Alert(BaseModel):
    id: int
    threat_id: int
    rule_name: str
    severity: Severity
    message: str
    acknowledged: bool = False
    created_at: datetime


class Incident(BaseModel):
    id: int
    title: str
    description: str
    severity: Severity
    status: ThreatStatus = ThreatStatus.OPEN
    threat_ids: list[int]
    timeline: list[dict]
    created_at: datetime


class Finding(BaseModel):
    type: str
    severity: Severity
    title: str
    file_path: str
    line_number: int
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None


class ScanResult(BaseModel):
    target: str
    scan_type: str
    findings: list[Finding]
    risk_score: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
