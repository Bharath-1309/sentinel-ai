from datetime import datetime

from .models import SecurityEvent


def security_event_to_detection_data(
    event: SecurityEvent,
) -> dict:
    """
    Convert a normalized SecurityEvent into the data format
    expected by SentinelAI's existing detection layer.
    """

    return {
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "username": event.username,
        "ip": event.source_ip,
        "source_ip": event.source_ip,
        "host": event.host,
        "message": event.message,
        "raw_log": event.raw_log,
        "source": event.source,
    }


def events_to_detection_data(
    events: list[SecurityEvent],
) -> list[dict]:
    """
    Convert multiple normalized security events into
    detection-engine compatible dictionaries.
    """

    return [
        security_event_to_detection_data(event)
        for event in events
    ]