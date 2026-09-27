from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityEvent:
    timestamp: datetime
    source: str
    event_type: str
    username: str | None
    source_ip: str | None
    host: str | None
    message: str
    raw_log: str