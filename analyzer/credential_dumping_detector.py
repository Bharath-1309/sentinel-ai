from dataclasses import dataclass
from datetime import datetime


@dataclass
class CredentialDumpingAlert:
    type: str
    timestamp: datetime
    username: str | None
    ip: str
    failed_attempts: int
    successful_login: bool
    risk: str
    mitre: dict | None = None

    def __getitem__(self, key):
        return getattr(self, key)

    def get(self, key, default=None):
        return getattr(self, key, default)


class CredentialDumpingDetector:

    def detect(
        self,
        source_ip,
        evidence_count,
        timestamp,
        username=None,
        threshold=1
    ):
        if evidence_count < threshold:
            return None

        return CredentialDumpingAlert(
            type="Credential Dumping",
            timestamp=timestamp,
            username=username,
            ip=source_ip,
            failed_attempts=evidence_count,
            successful_login=False,
            risk="CRITICAL"
        )