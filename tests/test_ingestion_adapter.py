from datetime import datetime

from analyzer.ingestion.adapter import (
    events_to_detection_data,
    security_event_to_detection_data,
)
from analyzer.ingestion.models import SecurityEvent


def create_event():
    return SecurityEvent(
        timestamp=datetime(2026, 9, 18, 10, 15, 30),
        source="linux",
        event_type="authentication_failure",
        username="admin",
        source_ip="192.168.1.50",
        host="server",
        message="SSH authentication failure",
        raw_log=(
            "Sep 18 10:15:30 server sshd[1234]: "
            "Failed password for admin from "
            "192.168.1.50 port 22 ssh2"
        ),
    )


def test_security_event_to_detection_data():
    event = create_event()

    data = security_event_to_detection_data(event)

    assert data["timestamp"] == event.timestamp
    assert data["event_type"] == "authentication_failure"
    assert data["username"] == "admin"
    assert data["ip"] == "192.168.1.50"
    assert data["source_ip"] == "192.168.1.50"
    assert data["host"] == "server"
    assert data["source"] == "linux"


def test_events_to_detection_data():
    events = [
        create_event(),
        create_event(),
    ]

    data = events_to_detection_data(events)

    assert len(data) == 2
    assert data[0]["username"] == "admin"
    assert data[1]["source_ip"] == "192.168.1.50"


def test_empty_events():
    data = events_to_detection_data([])

    assert data == []