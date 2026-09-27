from pathlib import Path

from .linux import LinuxAuthLogParser
from .windows import WindowsEventParser
from .network import NetworkLogParser
from .models import SecurityEvent


class UnifiedIngestionPipeline:

    def __init__(self):
        self.linux_parser = LinuxAuthLogParser()
        self.windows_parser = WindowsEventParser()
        self.network_parser = NetworkLogParser()

    def ingest_linux(
        self,
        log_file: str | Path,
    ) -> list[SecurityEvent]:

        return self.linux_parser.parse_file(log_file)

    def ingest_windows(
        self,
        log_file: str | Path,
    ) -> list[SecurityEvent]:

        return self.windows_parser.parse_file(log_file)

    def ingest_network(
        self,
        log_file: str | Path,
    ) -> list[SecurityEvent]:

        return self.network_parser.parse_file(log_file)

    def ingest(
        self,
        linux_log: str | Path | None = None,
        windows_log: str | Path | None = None,
        network_log: str | Path | None = None,
    ) -> list[SecurityEvent]:

        events: list[SecurityEvent] = []

        if linux_log is not None:
            events.extend(
                self.ingest_linux(linux_log)
            )

        if windows_log is not None:
            events.extend(
                self.ingest_windows(windows_log)
            )

        if network_log is not None:
            events.extend(
                self.ingest_network(network_log)
            )

        events.sort(
            key=lambda event: event.timestamp
        )

        return events