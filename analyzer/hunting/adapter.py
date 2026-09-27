from analyzer.ingestion.models import SecurityEvent


def security_event_to_hunting_data(event):
    if isinstance(event, SecurityEvent):
        return {
            "timestamp": event.timestamp,
            "source": event.source,
            "event_type": event.event_type,
            "username": event.username,
            "source_ip": event.source_ip,
            "host": event.host,
            "message": event.message,
            "raw_log": event.raw_log,
        }

    if isinstance(event, dict):
        return {
            "timestamp": event.get("timestamp"),
            "source": event.get("source"),
            "event_type": event.get("event_type"),
            "username": event.get("username"),
            "source_ip": event.get(
                "source_ip",
                event.get("ip"),
            ),
            "host": event.get("host"),
            "message": event.get("message"),
            "raw_log": event.get("raw_log"),
        }

    raise TypeError(
        f"Unsupported event type: {type(event).__name__}"
    )


def security_events_to_hunting_data(events):
    return [
        security_event_to_hunting_data(event)
        for event in events
    ]