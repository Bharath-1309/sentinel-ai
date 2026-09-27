from collections import defaultdict

from .models import BehaviorEvent, UserProfile


class UEBAFeatureExtractor:

    def extract_user_profiles(
        self,
        events: list[BehaviorEvent],
    ) -> dict[str, UserProfile]:

        profiles = defaultdict(
            lambda: UserProfile(username="")
        )

        for event in events:

            if not event.username:
                continue

            if event.username not in profiles:
                profiles[event.username] = UserProfile(
                    username=event.username
                )

            profile = profiles[event.username]

            profile.total_events += 1

            if event.event_type == "authentication_failure":
                profile.failed_logins += 1

            elif event.event_type == "authentication_success":
                profile.successful_logins += 1

            if event.source_ip:
                profile.unique_source_ips.add(
                    event.source_ip
                )

            if event.host:
                profile.unique_hosts.add(
                    event.host
                )

        return dict(profiles)