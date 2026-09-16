from dataclasses import dataclass
from datetime import datetime


@dataclass
class WindowsAuthAlert:
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


class WindowsAuthDetector:

    def detect_brute_force(
        self,
        username,
        source_ip,
        failed_attempts,
        timestamp,
        threshold=3
    ):
        if failed_attempts < threshold:
            return None

        risk = "HIGH"

        if failed_attempts >= 10:
            risk = "CRITICAL"

        return WindowsAuthAlert(
            type="Windows Authentication Brute Force",
            timestamp=timestamp,
            username=username,
            ip=source_ip,
            failed_attempts=failed_attempts,
            successful_login=False,
            risk=risk
        )