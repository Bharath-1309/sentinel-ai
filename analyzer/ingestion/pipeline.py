from pathlib import Path

from .adapter import events_to_detection_data
from .linux import LinuxAuthLogParser


class LinuxIngestionPipeline:

    def __init__(self):
        self.parser = LinuxAuthLogParser()

    def ingest(self, log_file: str | Path) -> list[dict]:
        """
        Read a Linux authentication log and return
        normalized events in detection-engine compatible format.
        """

        events = self.parser.parse_file(log_file)

        return events_to_detection_data(events)