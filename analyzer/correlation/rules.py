from dataclasses import dataclass


@dataclass
class CorrelationRule:
    correlation_id: str
    name: str
    description: str
    required_alert_types: set[str]
    severity: str
    window_minutes: int = 15
    enabled: bool = True