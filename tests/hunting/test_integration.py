from datetime import datetime

from analyzer.hunting.adapter import security_events_to_hunting_data
from analyzer.hunting.engine import ThreatHuntingEngine
from analyzer.hunting.models import (
    HuntingQuery,
    HuntingSearch,
    HuntingTimeRange,
)
from analyzer.ingestion.models import SecurityEvent


def test_hunting_engine_searches_real_security_events():
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
            timestamp=datetime(2026, 9, 20, 10, 10, 0),
            source="linux",
            event_type="authentication_success",
            username="admin",
            source_ip="192.168.1.50",
            host="server01",
            message="Successful SSH login",
            raw_log="Accepted password for admin",
        ),
    ]

    hunting_events = security_events_to_hunting_data(events)

    query = HuntingSearch(
        conditions=HuntingQuery(
            field="event_type",
            operator="equals",
            value="authentication_failure",
        ),
        time_range=HuntingTimeRange(
            start=datetime(2026, 9, 20, 10, 0, 0),
            end=datetime(2026, 9, 20, 10, 30, 0),
        ),
    )

    results = ThreatHuntingEngine().search(
        hunting_events,
        query,
    )

    assert len(results) == 1
    assert results[0]["username"] == "admin"
    assert results[0]["source_ip"] == "192.168.1.50"