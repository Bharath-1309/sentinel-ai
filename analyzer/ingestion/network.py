import re
from datetime import datetime

from .base import LogParser
from .models import SecurityEvent


class NetworkLogParser(LogParser):

    CONNECTION_PATTERN = re.compile(
        r"(?P<timestamp>\d{4}\s+\w{3}\s+\d{2}\s+"
        r"\d{2}:\d{2}:\d{2}).*?"
        r"Connection attempt from "
        r"(?P<ip>[\d.]+) "
        r"to port (?P<port>\d+)"
    )

    def parse_line(self, line: str) -> SecurityEvent | None:

        match = self.CONNECTION_PATTERN.search(line)

        if not match:
            return None

        timestamp = datetime.strptime(
            match.group("timestamp"),
            "%Y %b %d %H:%M:%S",
        )

        source_ip = match.group("ip")
        port = int(match.group("port"))

        return SecurityEvent(
            timestamp=timestamp,
            source="network",
            event_type="network_connection_attempt",
            username=None,
            source_ip=source_ip,
            host=None,
            message=f"Connection attempt to port {port}",
            raw_log=line.strip(),
        )

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