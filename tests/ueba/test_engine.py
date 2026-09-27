from analyzer.ueba.engine import UEBAEngine
from analyzer.ueba.models import (
    UserProfile,
    BehaviorBaseline,
)


def test_detect_high_failed_login_anomaly():

    profiles = {
        "admin": UserProfile(
            username="admin",
            failed_logins=12,
            successful_logins=1,
            unique_source_ips={
                "192.168.1.50",
            },
            unique_hosts={
                "server",
            },
        )
    }

    baselines = {
        "admin": BehaviorBaseline(
            username="admin",
            average_failed_logins=2.0,
            average_successful_logins=1.0,
            usual_source_ips={
                "192.168.1.50",
            },
            usual_hosts={
                "server",
            },
        )
    }

    findings = UEBAEngine().analyze(
        profiles,
        baselines,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.username == "admin"
    assert finding.anomaly_score == 40.0
    assert finding.severity == "MEDIUM"

    assert (
        "Failed-login volume significantly above baseline"
        in finding.reasons
    )


def test_detect_new_source_ip():

    profiles = {
        "admin": UserProfile(
            username="admin",
            failed_logins=1,
            unique_source_ips={
                "192.168.1.50",
                "10.10.10.25",
            },
            unique_hosts={
                "server",
            },
        )
    }

    baselines = {
        "admin": BehaviorBaseline(
            username="admin",
            average_failed_logins=1.0,
            usual_source_ips={
                "192.168.1.50",
            },
            usual_hosts={
                "server",
            },
        )
    }

    findings = UEBAEngine().analyze(
        profiles,
        baselines,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.anomaly_score == 30.0
    assert finding.severity == "MEDIUM"

    assert (
        "New source IP observed"
        in finding.reasons
    )


def test_detect_new_host():

    profiles = {
        "admin": UserProfile(
            username="admin",
            failed_logins=1,
            unique_source_ips={
                "192.168.1.50",
            },
            unique_hosts={
                "server",
                "database",
            },
        )
    }

    baselines = {
        "admin": BehaviorBaseline(
            username="admin",
            average_failed_logins=1.0,
            usual_source_ips={
                "192.168.1.50",
            },
            usual_hosts={
                "server",
            },
        )
    }

    findings = UEBAEngine().analyze(
        profiles,
        baselines,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.anomaly_score == 20.0
    assert finding.severity == "LOW"

    assert (
        "New host observed"
        in finding.reasons
    )


def test_combine_multiple_anomalies():

    profiles = {
        "admin": UserProfile(
            username="admin",
            failed_logins=12,
            successful_logins=2,
            unique_source_ips={
                "192.168.1.50",
                "10.10.10.25",
            },
            unique_hosts={
                "server",
                "database",
            },
        )
    }

    baselines = {
        "admin": BehaviorBaseline(
            username="admin",
            average_failed_logins=2.0,
            average_successful_logins=2.0,
            usual_source_ips={
                "192.168.1.50",
            },
            usual_hosts={
                "server",
            },
        )
    }

    findings = UEBAEngine().analyze(
        profiles,
        baselines,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.anomaly_score == 90.0
    assert finding.severity == "CRITICAL"

    assert len(finding.reasons) == 3


def test_no_anomaly_produces_no_finding():

    profiles = {
        "admin": UserProfile(
            username="admin",
            failed_logins=2,
            successful_logins=2,
            unique_source_ips={
                "192.168.1.50",
            },
            unique_hosts={
                "server",
            },
        )
    }

    baselines = {
        "admin": BehaviorBaseline(
            username="admin",
            average_failed_logins=2.0,
            average_successful_logins=2.0,
            usual_source_ips={
                "192.168.1.50",
            },
            usual_hosts={
                "server",
            },
        )
    }

    findings = UEBAEngine().analyze(
        profiles,
        baselines,
    )

    assert findings == []


def test_missing_baseline_is_ignored():

    profiles = {
        "admin": UserProfile(
            username="admin",
            failed_logins=10,
        )
    }

    findings = UEBAEngine().analyze(
        profiles,
        {}
    )

    assert findings == []