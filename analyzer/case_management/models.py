from dataclasses import dataclass, field
from datetime import datetime


CASE_STATUSES = {
    "OPEN",
    "INVESTIGATING",
    "CONTAINED",
    "RESOLVED",
    "CLOSED",
}

CASE_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


@dataclass
class CaseNote:
    note_id: int | None
    author: str
    content: str
    created_at: datetime


@dataclass
class CaseEvidence:
    evidence_id: int | None
    evidence_type: str
    value: str
    source: str | None
    created_at: datetime


@dataclass
class Case:
    case_id: str
    incident_id: str
    title: str
    description: str
    severity: str
    status: str
    assigned_to: str | None
    created_at: datetime
    updated_at: datetime
    notes: list[CaseNote] = field(default_factory=list)
    evidence: list[CaseEvidence] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    mitre_techniques: list[dict] = field(default_factory=list)
    ai_investigation: dict | None = None