from datetime import datetime

from analyzer.ueba.features import UEBAFeatureExtractor
from analyzer.ueba.models import BehaviorEvent


def test_extract_user_profile():

    events = [
        BehaviorEvent(
            timestamp=datetime(2026, 9, 15, 10, 21, 1),
            username="admin",
            source_ip="192.168.1.50",
            host="server",
            event_type="authentication_failure",
        ),
        BehaviorEvent(
            timestamp=datetime(2026, 9, 15, 10, 21, 5),
            username="admin",
            source_ip="192.168.1.50",
            host="server",
            event_type="authentication_failure",
        ),
        BehaviorEvent(
            timestamp=datetime(2026, 9, 15, 10, 21, 9),
            username="admin",
            source_ip="192.168.1.50",
            host="server",
            event_type="authentication_success",
        ),
    ]

    profiles = UEBAFeatureExtractor().extract_user_profiles(
        events
    )

    assert "admin" in profiles

    profile = profiles["admin"]

    assert profile.username == "admin"
    assert profile.total_events == 3
    assert profile.failed_logins == 2
    assert profile.successful_logins == 1

    assert profile.unique_source_ips == {
        "192.168.1.50"
    }

    assert profile.unique_hosts == {
        "server"
    }


def test_extract_multiple_users():

    events = [
        BehaviorEvent(
            timestamp=datetime(2026, 9, 15, 10, 21, 1),
            username="admin",
            source_ip="192.168.1.50",
            host="server",
            event_type="authentication_failure",
        ),
        BehaviorEvent(
            timestamp=datetime(2026, 9, 15, 10, 22, 1),
            username="root",
            source_ip="10.10.10.25",
            host="server",
            event_type="authentication_failure",
        ),
    ]

    profiles = UEBAFeatureExtractor().extract_user_profiles(
        events
    )

    assert len(profiles) == 2

    assert profiles["admin"].failed_logins == 1
    assert profiles["root"].failed_logins == 1


def test_ignore_events_without_username():

    events = [
        BehaviorEvent(
            timestamp=datetime(2026, 9, 15, 10, 21, 1),
            username=None,
            source_ip="192.168.1.50",
            host="server",
            event_type="authentication_failure",
        )
    ]

    profiles = UEBAFeatureExtractor().extract_user_profiles(
        events
    )

    assert profiles == {}


def test_track_multiple_source_ips_and_hosts():

    events = [
        BehaviorEvent(
            timestamp=datetime(2026, 9, 15, 10, 21, 1),
            username="admin",
            source_ip="192.168.1.50",
            host="server-01",
            event_type="authentication_failure",
        ),
        BehaviorEvent(
            timestamp=datetime(2026, 9, 15, 10, 22, 1),
            username="admin",
            source_ip="10.10.10.25",
            host="server-02",
            event_type="authentication_success",
        ),
    ]

    profiles = UEBAFeatureExtractor().extract_user_profiles(
        events
    )

    profile = profiles["admin"]

    assert profile.unique_source_ips == {
        "192.168.1.50",
        "10.10.10.25",
    }

    assert profile.unique_hosts == {
        "server-01",
        "server-02",
    }