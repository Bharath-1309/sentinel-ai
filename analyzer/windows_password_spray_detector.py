from dataclasses import dataclass
from datetime import datetime


@dataclass
class WindowsPasswordSprayAlert:
    type: str
    timestamp: datetime
    username: str
    ip: str
    failed_attempts: int
    successful_login: bool
    risk: str
    mitre: dict | None = None

    def __getitem__(self, key):
        return getattr(self, key)

    def get(self, key, default=None):
        return getattr(self, key, default)


class WindowsPasswordSprayDetector:

    def detect(
        self,
        source_ip,
        username_attempts,
        timestamp,
        threshold=3
    ):
        if len(username_attempts) < threshold:
            return None

        targeted_users = sorted(username_attempts)

        return WindowsPasswordSprayAlert(
            type="Windows Password Spraying",
            timestamp=timestamp,
            username=", ".join(targeted_users),
            ip=source_ip,
            failed_attempts=len(targeted_users),
            successful_login=False,
            risk="HIGH"
        )