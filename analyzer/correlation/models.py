from dataclasses import dataclass, field


@dataclass
class CorrelationResult:
    correlation_id: str
    name: str
    description: str
    source_ip: str
    severity: str
    alert_count: int
    alerts: list[dict] = field(default_factory=list)
