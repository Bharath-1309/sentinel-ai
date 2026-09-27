from pathlib import Path

from analyzer.hunting.adapter import security_events_to_hunting_data
from analyzer.hunting.engine import ThreatHuntingEngine
from analyzer.hunting.models import HuntingQuery, HuntingSearch
from analyzer.ingestion.pipeline import LinuxIngestionPipeline


def test_hunting_uses_linux_ingestion_pipeline():
    log_file = Path("logs/auth.log")

    pipeline = LinuxIngestionPipeline()
    events = pipeline.ingest(log_file)

    assert events
    assert all("timestamp" in event for event in events)
    assert all("event_type" in event for event in events)

    hunting_events = security_events_to_hunting_data(events)

    query = HuntingSearch(
        conditions=HuntingQuery(
            field="event_type",
            operator="equals",
            value="authentication_failure",
        )
    )

    results = ThreatHuntingEngine().search(
        hunting_events,
        query,
    )

    assert results
    assert all(
        event["event_type"] == "authentication_failure"
        for event in results
    )