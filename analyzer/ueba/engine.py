from .models import (
    UserProfile,
    BehaviorBaseline,
    UEBAFinding,
)


class UEBAEngine:

    def analyze(
        self,
        profiles: dict[str, UserProfile],
        baselines: dict[str, BehaviorBaseline],
    ) -> list[UEBAFinding]:

        findings = []

        for username, profile in profiles.items():

            baseline = baselines.get(username)

            if baseline is None:
                continue

            score = 0.0
            reasons = []

            # -------------------------------------------------
            # FAILED LOGIN ANOMALY
            # -------------------------------------------------

            if (
                profile.failed_logins
                > baseline.average_failed_logins
            ):
                if baseline.average_failed_logins > 0:

                    ratio = (
                        profile.failed_logins
                        / baseline.average_failed_logins
                    )

                    if ratio >= 3:
                        score += 40
                        reasons.append(
                            "Failed-login volume significantly above baseline"
                        )

                    elif ratio >= 2:
                        score += 25
                        reasons.append(
                            "Failed-login volume above baseline"
                        )

            # -------------------------------------------------
            # NEW SOURCE IP
            # -------------------------------------------------

            new_source_ips = (
                profile.unique_source_ips
                - baseline.usual_source_ips
            )

            if new_source_ips:

                score += 30

                reasons.append(
                    "New source IP observed"
                )

            # -------------------------------------------------
            # NEW HOST
            # -------------------------------------------------

            new_hosts = (
                profile.unique_hosts
                - baseline.usual_hosts
            )

            if new_hosts:

                score += 20

                reasons.append(
                    "New host observed"
                )

            # -------------------------------------------------
            # SCORE LIMIT
            # -------------------------------------------------

            score = min(score, 100.0)

            # -------------------------------------------------
            # ONLY CREATE FINDING WHEN ANOMALY EXISTS
            # -------------------------------------------------

            if score <= 0:
                continue

            severity = self._severity(score)

            findings.append(
                UEBAFinding(
                    username=username,
                    anomaly_score=score,
                    severity=severity,
                    reasons=reasons,
                    observed_behavior={
                        "failed_logins": profile.failed_logins,
                        "successful_logins": (
                            profile.successful_logins
                        ),
                        "source_ips": list(
                            profile.unique_source_ips
                        ),
                        "hosts": list(
                            profile.unique_hosts
                        ),
                    },
                    baseline_behavior={
                        "average_failed_logins": (
                            baseline.average_failed_logins
                        ),
                        "average_successful_logins": (
                            baseline.average_successful_logins
                        ),
                        "usual_source_ips": list(
                            baseline.usual_source_ips
                        ),
                        "usual_hosts": list(
                            baseline.usual_hosts
                        ),
                    },
                )
            )

        return findings

    @staticmethod
    def _severity(score: float) -> str:

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 30:
            return "MEDIUM"

        return "LOW"