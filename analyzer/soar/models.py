from dataclasses import dataclass, field
from datetime import datetime


ACTION_STATUSES = {
    "PENDING",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "SKIPPED",
}

PLAYBOOK_STATUSES = {
    "PENDING",
    "RUNNING",
    "COMPLETED",
    "FAILED",
}


@dataclass
class SOARAction:
    action_id: str
    action_type: str
    description: str
    target: str | None = None
    status: str = "PENDING"
    result: str | None = None
    executed_at: datetime | None = None


@dataclass
class SOARPlaybook:
    playbook_id: str
    name: str
    description: str
    incident_types: list[str] = field(default_factory=list)
    minimum_severity: str = "LOW"
    actions: list[str] = field(default_factory=list)


@dataclass
class SOARExecution:
    execution_id: str
    case_id: str
    playbook_id: str
    playbook_name: str
    status: str
    started_at: datetime
    completed_at: datetime | None = None
    actions: list[SOARAction] = field(default_factory=list)
    error: str | None = None