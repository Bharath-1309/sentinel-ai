from dataclasses import dataclass
from datetime import datetime


@dataclass
class NetworkScanAlert:
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


class NetworkScanDetector:

    def detect(
        self,
        source_ip,
        target_ports,
        timestamp,
        threshold=5
    ):
        if len(target_ports) < threshold:
            return None

        return NetworkScanAlert(
            type="Network Service Scanning",
            timestamp=timestamp,
            username=None,
            ip=source_ip,
            failed_attempts=len(target_ports),
            successful_login=False,
            risk="HIGH"
        )