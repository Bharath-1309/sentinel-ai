from abc import ABC, abstractmethod

from .models import SecurityEvent


class LogParser(ABC):

    @abstractmethod
    def parse_line(self, line: str) -> SecurityEvent | None:
        """
        Convert one raw log line into a normalized SecurityEvent.
        """
        raise NotImplementedError