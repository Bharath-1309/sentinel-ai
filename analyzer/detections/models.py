from dataclasses import dataclass


@dataclass
class DetectionRule:
    rule_id: str
    name: str
    description: str
    event_type: str
    threshold: int
    window_minutes: int
    severity: str
    mitre_technique: str
    mitre_tactic: str
    enabled: bool = True