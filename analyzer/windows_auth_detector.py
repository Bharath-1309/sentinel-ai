from dataclasses import dataclass
from datetime import datetime


@dataclass
class WindowsAuthAlert:
    type: str
    timestamp: datetime
    username: str | None
    source_ip: str
    failed_attempts: int
    risk: str


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
            source_ip=source_ip,
            failed_attempts=failed_attempts,
            risk=risk
        )