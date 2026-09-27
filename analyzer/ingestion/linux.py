import re
from datetime import datetime
from pathlib import Path

from .base import LogParser
from .models import SecurityEvent


class LinuxAuthLogParser(LogParser):

    FAILED_PASSWORD_PATTERN = re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+"
        r"(?P<host>\S+)\s+"
        r".*?"
        r"Failed password for "
        r"(invalid user )?"
        r"(?P<username>\S+) "
        r"from (?P<ip>\S+)"
    )

    ACCEPTED_PASSWORD_PATTERN = re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+"
        r"(?P<host>\S+)\s+"
        r".*?"
        r"Accepted password for "
        r"(?P<username>\S+) "
        r"from (?P<ip>\S+)"
    )

    def parse_line(self, line: str) -> SecurityEvent | None:

        match = self.FAILED_PASSWORD_PATTERN.search(line)

        if match:
            return SecurityEvent(
                timestamp=self._parse_timestamp(
                    match.group("timestamp")
                ),
                source="linux",
                event_type="authentication_failure",
                username=match.group("username"),
                source_ip=match.group("ip"),
                host=match.group("host"),
                message="SSH authentication failure",
                raw_log=line.strip(),
            )

        match = self.ACCEPTED_PASSWORD_PATTERN.search(line)

        if match:
            return SecurityEvent(
                timestamp=self._parse_timestamp(
                    match.group("timestamp")
                ),
                source="linux",
                event_type="authentication_success",
                username=match.group("username"),
                source_ip=match.group("ip"),
                host=match.group("host"),
                message="SSH authentication success",
                raw_log=line.strip(),
            )

        return None

    def parse_file(self, log_file: str | Path) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []

        with open(
            log_file,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file:

            for line in file:
                line = line.strip()

                if not line:
                    continue

                event = self.parse_line(line)

                if event is not None:
                    events.append(event)

        return events

    @staticmethod
    def _parse_timestamp(value: str) -> datetime:

        current_year = datetime.now().year

        return datetime.strptime(
            f"{current_year} {value}",
            "%Y %b %d %H:%M:%S",
        )