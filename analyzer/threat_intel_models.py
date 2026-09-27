from dataclasses import dataclass, field
from datetime import datetime


SUPPORTED_IOC_TYPES = {
    "ip",
    "domain",
    "url",
    "hash",
}


@dataclass
class IOC:
    value: str
    ioc_type: str


@dataclass
class ThreatIntelResult:
    value: str
    ioc_type: str
    malicious: bool
    confidence: int
    threat: str | None
    source: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: list[str] = field(default_factory=list)
    provider_results: list[dict] = field(default_factory=list)