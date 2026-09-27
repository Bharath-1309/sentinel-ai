from .models import UserProfile, BehaviorBaseline


class UEBABaselineBuilder:

    def build_baselines(
        self,
        historical_profiles: list[dict[str, UserProfile]],
    ) -> dict[str, BehaviorBaseline]:

        if not historical_profiles:
            return {}

        usernames = set()

        for profiles in historical_profiles:
            usernames.update(profiles.keys())

        baselines = {}

        for username in usernames:

            periods = [
                profiles[username]
                for profiles in historical_profiles
                if username in profiles
            ]

            if not periods:
                continue

            average_failed_logins = (
                sum(
                    profile.failed_logins
                    for profile in periods
                )
                / len(periods)
            )

            average_successful_logins = (
                sum(
                    profile.successful_logins
                    for profile in periods
                )
                / len(periods)
            )

            usual_source_ips = set()

            usual_hosts = set()

            for profile in periods:
                usual_source_ips.update(
                    profile.unique_source_ips
                )
                usual_hosts.update(
                    profile.unique_hosts
                )

            baselines[username] = BehaviorBaseline(
                username=username,
                average_failed_logins=average_failed_logins,
                average_successful_logins=average_successful_logins,
                usual_source_ips=usual_source_ips,
                usual_hosts=usual_hosts,
            )

        return baselines