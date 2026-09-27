from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class BehaviorEvent:
    timestamp: datetime
    username: str | None
    source_ip: str | None
    host: str | None
    event_type: str


@dataclass
class UserProfile:
    username: str
    total_events: int = 0
    failed_logins: int = 0
    successful_logins: int = 0
    unique_source_ips: set[str] = field(
        default_factory=set
    )
    unique_hosts: set[str] = field(
        default_factory=set
    )


@dataclass
class BehaviorBaseline:
    username: str
    average_failed_logins: float = 0.0
    average_successful_logins: float = 0.0
    usual_source_ips: set[str] = field(
        default_factory=set
    )
    usual_hosts: set[str] = field(
        default_factory=set
    )


@dataclass
class UEBAFinding:
    username: str
    anomaly_score: float
    severity: str
    reasons: list[str] = field(
        default_factory=list
    )
    observed_behavior: dict = field(
        default_factory=dict
    )
    baseline_behavior: dict = field(
        default_factory=dict
    )