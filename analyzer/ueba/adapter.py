from analyzer.ingestion.models import SecurityEvent

from .models import BehaviorEvent


def security_event_to_behavior_event(
    event: SecurityEvent,
) -> BehaviorEvent:

    if not isinstance(event, SecurityEvent):
        raise TypeError(
            f"Unsupported event type: {type(event).__name__}"
        )

    return BehaviorEvent(
        timestamp=event.timestamp,
        username=event.username,
        source_ip=event.source_ip,
        host=event.host,
        event_type=event.event_type,
    )


def security_events_to_behavior_events(
    events: list[SecurityEvent],
) -> list[BehaviorEvent]:

    return [
        security_event_to_behavior_event(event)
        for event in events
    ]