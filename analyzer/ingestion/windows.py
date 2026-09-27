import re
from datetime import datetime

from .base import LogParser
from .models import SecurityEvent


class WindowsEventParser(LogParser):

    FAILED_LOGIN_PATTERN = re.compile(
        r"(?P<timestamp>\d{4}\s+\w{3}\s+\d{2}\s+"
        r"\d{2}:\d{2}:\d{2}).*?"
        r"Failed Windows login for "
        r"(?P<username>\w+) "
        r"from (?P<ip>[\d.]+)"
    )

    SUCCESSFUL_LOGIN_PATTERN = re.compile(
        r"(?P<timestamp>\d{4}\s+\w{3}\s+\d{2}\s+"
        r"\d{2}:\d{2}:\d{2}).*?"
        r"Successful Windows login for "
        r"(?P<username>\w+) "
        r"from (?P<ip>[\d.]+)"
    )

    def parse_line(self, line: str) -> SecurityEvent | None:

        match = self.FAILED_LOGIN_PATTERN.search(line)

        if match:
            return SecurityEvent(
                timestamp=self._parse_timestamp(
                    match.group("timestamp")
                ),
                source="windows",
                event_type="authentication_failure",
                username=match.group("username"),
                source_ip=match.group("ip"),
                host=None,
                message="Windows authentication failure",
                raw_log=line.strip(),
            )

        match = self.SUCCESSFUL_LOGIN_PATTERN.search(line)

        if match:
            return SecurityEvent(
                timestamp=self._parse_timestamp(
                    match.group("timestamp")
                ),
                source="windows",
                event_type="authentication_success",
                username=match.group("username"),
                source_ip=match.group("ip"),
                host=None,
                message="Windows authentication success",
                raw_log=line.strip(),
            )

        return None

    def parse_file(self, log_file: str) -> list[SecurityEvent]:

        events = []

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

        return datetime.strptime(
            value,
            "%Y %b %d %H:%M:%S",
        )