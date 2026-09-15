from datetime import datetime, timedelta
from dataclasses import dataclass


@dataclass
class SecurityAlert:
    type: str
    timestamp: datetime
    username: str | None
    ip: str
    failed_attempts: int
    successful_login: bool
    risk: str
    mitre: dict | None = None
    targeted_users: list[str] | None = None
    threat_intelligence: dict | None = None

    def __getitem__(self, key):
        if key == "targeted_user_count":
            return len(self.targeted_users or [])

        return getattr(self, key)

    def get(self, key, default=None):
        if key == "targeted_user_count":
            return len(self.targeted_users or [])

        return getattr(self, key, default)


class DetectionEngine:

    def detect_brute_force(
        self,
        username,
        ip_address,
        timestamps,
        threshold,
        window_minutes,
        successful_login=False
    ):
        if not timestamps:
            return None

        window_start = timestamps[-1] - timedelta(minutes=window_minutes)

        recent_attempts = [
            timestamp
            for timestamp in timestamps
            if timestamp >= window_start
        ]

        if len(recent_attempts) < threshold:
            return None

        risk = "CRITICAL" if successful_login else "MEDIUM"

        return SecurityAlert(
            type="SSH Brute Force",
            timestamp=timestamps[-1],
            username=username,
            ip=ip_address,
            failed_attempts=len(recent_attempts),
            successful_login=successful_login,
            risk=risk
        )

    def detect_password_spraying(
        self,
        ip_address,
        username_attempts,
        threshold,
        timestamp
    ):
        if len(username_attempts) < threshold:
            return None

        targeted_users = sorted(username_attempts)

        return SecurityAlert(
            type="SSH Password Spraying",
            timestamp=timestamp,
            username=", ".join(targeted_users),
            ip=ip_address,
            failed_attempts=len(targeted_users),
            successful_login=False,
            risk="HIGH",
            targeted_users=targeted_users
        )