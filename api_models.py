from datetime import datetime

from pydantic import BaseModel


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


class AnalysisResponse(BaseModel):
    alerts: list[AlertResponse]
    incidents: list[IncidentResponse]