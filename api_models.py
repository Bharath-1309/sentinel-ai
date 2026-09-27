from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from analyzer.hunting.models import (
    HUNTING_FIELDS,
    HUNTING_OPERATORS,
)


class MitreTechnique(BaseModel):
    technique_id: str
    technique: str
    tactic: str


class ThreatIntelligenceResponse(BaseModel):
    ip: str
    malicious: bool
    threat: str | None = None
    confidence: int
    source: str


class AlertResponse(BaseModel):
    type: str
    timestamp: datetime
    username: str | None
    ip: str
    failed_attempts: int
    successful_login: bool
    risk: str
    mitre: MitreTechnique | None = None
    targeted_users: list[str] | None = None
    threat_intelligence: ThreatIntelligenceResponse | None = None


class AIInvestigationResponse(BaseModel):
    incident_id: str
    type: str
    risk: str
    source_ip: str
    investigation_status: str
    analysis: str | None = None
    recommendations: list[str]


class ResponsePlaybook(BaseModel):
    incident_id: str
    incident_type: str
    severity: str
    actions: list[str]


class IncidentResponse(BaseModel):
    incident_id: str
    type: str
    source_ip: str
    risk: str
    risk_score: int
    alert_count: int
    start_time: datetime | None
    end_time: datetime | None
    status: str
    mitre_techniques: list[MitreTechnique]
    evidence: list[AlertResponse]
    ai_investigation: AIInvestigationResponse | None = None
    response_playbook: ResponsePlaybook | None = None


class AnalysisResponse(BaseModel):
    alerts: list[AlertResponse]
    incidents: list[IncidentResponse]


class HuntingQueryRequest(BaseModel):
    field: str
    operator: str
    value: str

    @field_validator("field")
    @classmethod
    def validate_field(cls, value: str) -> str:
        if value not in HUNTING_FIELDS:
            raise ValueError(f"Unsupported hunting field: {value}")
        return value

    @field_validator("operator")
    @classmethod
    def validate_operator(cls, value: str) -> str:
        if value not in HUNTING_OPERATORS:
            raise ValueError(f"Unsupported hunting operator: {value}")
        return value


class HuntingQueryGroupRequest(BaseModel):
    queries: list[HuntingQueryRequest] = Field(min_length=1)
    logic: str = "AND"

    @field_validator("logic")
    @classmethod
    def validate_logic(cls, value: str) -> str:
        value = value.upper()

        if value not in {"AND", "OR"}:
            raise ValueError("logic must be either AND or OR")

        return value


class HuntingTimeRangeRequest(BaseModel):
    start: datetime
    end: datetime

    @field_validator("end")
    @classmethod
    def validate_time_range(cls, value: datetime, info) -> datetime:
        start = info.data.get("start")

        if start is not None and value < start:
            raise ValueError("end must be greater than or equal to start")

        return value


class HuntingSearchRequest(BaseModel):
    query: HuntingQueryRequest | None = None
    query_group: HuntingQueryGroupRequest | None = None
    time_range: HuntingTimeRangeRequest | None = None
    limit: int = Field(default=100, ge=1, le=1000)
    sort_by: str = "timestamp"
    sort_order: str = "desc"

    @field_validator("sort_by")
    @classmethod
    def validate_sort_by(cls, value: str) -> str:
        if value not in HUNTING_FIELDS:
            raise ValueError(f"Unsupported sort field: {value}")
        return value

    @field_validator("sort_order")
    @classmethod
    def validate_sort_order(cls, value: str) -> str:
        value = value.lower()

        if value not in {"asc", "desc"}:
            raise ValueError("sort_order must be either asc or desc")

        return value


class IOCEnrichmentRequest(BaseModel):
    value: str = Field(min_length=1, max_length=2048)


class IOCResponse(BaseModel):
    value: str
    ioc_type: str | None
    valid: bool
    enriched: bool
    result: dict | None = None


# ============================================================
# CASE MANAGEMENT
# ============================================================

class CaseCreateRequest(BaseModel):
    incident_id: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=5000)
    severity: str = "MEDIUM"
    assigned_to: str | None = Field(default=None, max_length=100)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        value = value.upper()

        if value not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError(
                "severity must be LOW, MEDIUM, HIGH, or CRITICAL"
            )

        return value


class CaseUpdateRequest(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=5000)
    severity: str | None = None
    status: str | None = None
    assigned_to: str | None = Field(default=None, max_length=100)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str | None) -> str | None:
        if value is None:
            return value

        value = value.upper()

        if value not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError(
                "severity must be LOW, MEDIUM, HIGH, or CRITICAL"
            )

        return value

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str | None) -> str | None:
        if value is None:
            return value

        value = value.upper()

        if value not in {
            "OPEN",
            "INVESTIGATING",
            "CONTAINED",
            "RESOLVED",
            "CLOSED",
        }:
            raise ValueError(
                "status must be OPEN, INVESTIGATING, CONTAINED, "
                "RESOLVED, or CLOSED"
            )

        return value


class CaseNoteRequest(BaseModel):
    author: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=5000)


class CaseEvidenceRequest(BaseModel):
    evidence_type: str = Field(min_length=1, max_length=100)
    value: str = Field(min_length=1, max_length=5000)
    source: str | None = Field(default=None, max_length=255)