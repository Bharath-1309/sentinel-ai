from datetime import datetime

from analyzer.hunting.adapter import (
    security_event_to_hunting_data,
    security_events_to_hunting_data,
)
from analyzer.ingestion.models import SecurityEvent


def test_security_event_to_hunting_data():
    event = SecurityEvent(
        timestamp=datetime(2026, 9, 20, 10, 5, 0),
        source="linux",
        event_type="authentication_failure",
        username="admin",
        source_ip="192.168.1.50",
        host="server01",
        message="SSH authentication failure",
        raw_log="Failed password for admin",
    )

    result = security_event_to_hunting_data(event)

    assert result["event_type"] == "authentication_failure"
    assert result["username"] == "admin"
    assert result["source_ip"] == "192.168.1.50"
    assert result["host"] == "server01"
    assert result["source"] == "linux"


def test_security_events_to_hunting_data():
    events = [
        SecurityEvent(
            timestamp=datetime(2026, 9, 20, 10, 5, 0),
            source="linux",
            event_type="authentication_failure",
            username="admin",
            source_ip="192.168.1.50",
            host="server01",
            message="SSH authentication failure",
            raw_log="Failed password for admin",
        ),
        SecurityEvent(
            timestamp=datetime(2026, 9, 20, 10, 6, 0),
            source="linux",
            event_type="authentication_failure",
            username="root",
            source_ip="10.10.10.25",
            host="server01",
            message="SSH authentication failure",
            raw_log="Failed password for root",
        ),
    ]

    results = security_events_to_hunting_data(events)

    assert len(results) == 2
    assert results[0]["username"] == "admin"
    assert results[1]["username"] == "root"