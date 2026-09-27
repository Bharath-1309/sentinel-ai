from analyzer.ueba.baseline import UEBABaselineBuilder
from analyzer.ueba.models import UserProfile


def test_build_average_baseline_across_periods():

    historical_profiles = [
        {
            "admin": UserProfile(
                username="admin",
                failed_logins=2,
                successful_logins=10,
                unique_source_ips={
                    "192.168.1.50",
                },
                unique_hosts={
                    "server",
                },
            )
        },
        {
            "admin": UserProfile(
                username="admin",
                failed_logins=4,
                successful_logins=8,
                unique_source_ips={
                    "192.168.1.50",
                },
                unique_hosts={
                    "server",
                },
            )
        },
        {
            "admin": UserProfile(
                username="admin",
                failed_logins=6,
                successful_logins=12,
                unique_source_ips={
                    "10.10.10.25",
                },
                unique_hosts={
                    "server",
                    "database",
                },
            )
        },
    ]

    baselines = UEBABaselineBuilder().build_baselines(
        historical_profiles
    )

    baseline = baselines["admin"]

    assert baseline.username == "admin"

    assert baseline.average_failed_logins == 4.0

    assert baseline.average_successful_logins == 10.0

    assert baseline.usual_source_ips == {
        "192.168.1.50",
        "10.10.10.25",
    }

    assert baseline.usual_hosts == {
        "server",
        "database",
    }


def test_build_baselines_for_multiple_users():

    historical_profiles = [
        {
            "admin": UserProfile(
                username="admin",
                failed_logins=2,
            ),
            "root": UserProfile(
                username="root",
                failed_logins=4,
            ),
        },
        {
            "admin": UserProfile(
                username="admin",
                failed_logins=4,
            ),
            "root": UserProfile(
                username="root",
                failed_logins=6,
            ),
        },
    ]

    baselines = UEBABaselineBuilder().build_baselines(
        historical_profiles
    )

    assert len(baselines) == 2

    assert baselines["admin"].average_failed_logins == 3.0

    assert baselines["root"].average_failed_logins == 5.0


def test_user_missing_from_some_periods():

    historical_profiles = [
        {
            "admin": UserProfile(
                username="admin",
                failed_logins=2,
            )
        },
        {
            "admin": UserProfile(
                username="admin",
                failed_logins=4,
            ),
            "root": UserProfile(
                username="root",
                failed_logins=6,
            ),
        },
    ]

    baselines = UEBABaselineBuilder().build_baselines(
        historical_profiles
    )

    assert baselines["admin"].average_failed_logins == 3.0

    assert baselines["root"].average_failed_logins == 6.0


def test_empty_historical_profiles():

    baselines = UEBABaselineBuilder().build_baselines(
        []
    )

    assert baselines == {}