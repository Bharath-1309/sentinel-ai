from datetime import datetime

from analyzer.ueba.models import (
    BehaviorEvent,
    UserProfile,
    BehaviorBaseline,
    UEBAFinding,
)


def test_behavior_event_creation():

    event = BehaviorEvent(
        timestamp=datetime(2026, 9, 15, 10, 21, 1),
        username="admin",
        source_ip="192.168.1.50",
        host="server",
        event_type="authentication_failure",
    )

    assert event.username == "admin"
    assert event.source_ip == "192.168.1.50"
    assert event.host == "server"
    assert event.event_type == "authentication_failure"


def test_user_profile_defaults():

    profile = UserProfile(
        username="admin"
    )

    assert profile.username == "admin"
    assert profile.total_events == 0
    assert profile.failed_logins == 0
    assert profile.successful_logins == 0
    assert profile.unique_source_ips == set()
    assert profile.unique_hosts == set()


def test_user_profile_tracks_behavior():

    profile = UserProfile(
        username="admin",
        total_events=10,
        failed_logins=7,
        successful_logins=3,
        unique_source_ips={
            "192.168.1.50",
            "10.10.10.25",
        },
        unique_hosts={"server"},
    )

    assert profile.total_events == 10
    assert profile.failed_logins == 7
    assert profile.successful_logins == 3
    assert len(profile.unique_source_ips) == 2
    assert len(profile.unique_hosts) == 1


def test_behavior_baseline_defaults():

    baseline = BehaviorBaseline(
        username="admin"
    )

    assert baseline.username == "admin"
    assert baseline.average_failed_logins == 0.0
    assert baseline.average_successful_logins == 0.0
    assert baseline.usual_source_ips == set()
    assert baseline.usual_hosts == set()


def test_ueba_finding_creation():

    finding = UEBAFinding(
        username="admin",
        anomaly_score=92.0,
        severity="CRITICAL",
        reasons=[
            "Failed-login volume significantly above baseline",
            "New source IP observed",
        ],
        observed_behavior={
            "failed_logins": 12,
            "source_ip": "10.10.10.25",
        },
        baseline_behavior={
            "average_failed_logins": 1.2,
            "usual_source_ips": [
                "192.168.1.50",
            ],
        },
    )

    assert finding.username == "admin"
    assert finding.anomaly_score == 92.0
    assert finding.severity == "CRITICAL"
    assert len(finding.reasons) == 2
    assert finding.observed_behavior["failed_logins"] == 12