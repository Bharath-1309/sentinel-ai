from datetime import datetime

from analyzer.ingestion.models import SecurityEvent
from analyzer.ueba.adapter import (
    security_events_to_behavior_events,
)
from analyzer.ueba.features import UEBAFeatureExtractor
from analyzer.ueba.baseline import UEBABaselineBuilder
from analyzer.ueba.engine import UEBAEngine


def build_event(
    day,
    event_type,
    source_ip="192.168.1.50",
):
    return SecurityEvent(
        timestamp=datetime(
            2026,
            9,
            day,
            10,
            0,
            0,
        ),
        source="linux",
        event_type=event_type,
        username="admin",
        source_ip=source_ip,
        host="server",
        message="SSH authentication event",
        raw_log="authentication event",
    )


def test_ueba_uses_multiple_historical_periods():

    historical_events = [
        # Period 1: 2 failures
        build_event(
            1,
            "authentication_failure",
        ),
        build_event(
            1,
            "authentication_failure",
        ),

        # Period 2: 4 failures
        build_event(
            2,
            "authentication_failure",
        ),
        build_event(
            2,
            "authentication_failure",
        ),
        build_event(
            2,
            "authentication_failure",
        ),
        build_event(
            2,
            "authentication_failure",
        ),

        # Period 3: 6 failures
        build_event(
            3,
            "authentication_failure",
        ),
        build_event(
            3,
            "authentication_failure",
        ),
        build_event(
            3,
            "authentication_failure",
        ),
        build_event(
            3,
            "authentication_failure",
        ),
        build_event(
            3,
            "authentication_failure",
        ),
        build_event(
            3,
            "authentication_failure",
        ),
    ]

    current_events = [
        # Current period: 12 failures
        build_event(
            15,
            "authentication_failure",
            source_ip="10.10.10.25",
        )
        for _ in range(12)
    ]

    extractor = UEBAFeatureExtractor()

    # ---------------------------------------------------------
    # Build one profile per historical period
    # ---------------------------------------------------------

    historical_periods = []

    for day in (1, 2, 3):

        period_events = [
            event
            for event in historical_events
            if event.timestamp.day == day
        ]

        behavior_events = (
            security_events_to_behavior_events(
                period_events
            )
        )

        profiles = extractor.extract_user_profiles(
            behavior_events
        )

        historical_periods.append(profiles)

    # ---------------------------------------------------------
    # Build historical baseline
    # ---------------------------------------------------------

    baselines = (
        UEBABaselineBuilder()
        .build_baselines(historical_periods)
    )

    baseline = baselines["admin"]

    # (2 + 4 + 6) / 3 = 4
    assert baseline.average_failed_logins == 4.0

    # ---------------------------------------------------------
    # Build current profile
    # ---------------------------------------------------------

    current_behavior = (
        security_events_to_behavior_events(
            current_events
        )
    )

    current_profiles = (
        extractor.extract_user_profiles(
            current_behavior
        )
    )

    # ---------------------------------------------------------
    # Analyze current behavior
    # ---------------------------------------------------------

    findings = UEBAEngine().analyze(
        current_profiles,
        baselines,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.username == "admin"

    # 12 / 4 = 3x baseline
    assert finding.anomaly_score == 70.0

    assert finding.severity == "HIGH"

    assert (
        "Failed-login volume significantly above baseline"
        in finding.reasons
    )

    assert (
        "New source IP observed"
        in finding.reasons
    )