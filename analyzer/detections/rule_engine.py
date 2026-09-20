from datetime import timedelta

from .models import DetectionRule


class DetectionRuleEngine:

    def evaluate(
        self,
        rule: DetectionRule,
        events: list[dict],
    ) -> list[dict]:

        if not rule.enabled:
            return []

        matching_events = [
            event
            for event in events
            if event.get("event_type") == rule.event_type
        ]

        if not matching_events:
            return []

        alerts = []

        grouped_events = {}

        for event in matching_events:

            source_ip = event.get("source_ip") or event.get("ip")

            if not source_ip:
                continue

            grouped_events.setdefault(
                source_ip,
                [],
            ).append(event)

        for source_ip, source_events in grouped_events.items():

            source_events.sort(
                key=lambda event: event["timestamp"]
            )

            for index, event in enumerate(source_events):

                window_start = (
                    event["timestamp"]
                    - timedelta(
                        minutes=rule.window_minutes
                    )
                )

                window_events = [
                    item
                    for item in source_events[: index + 1]
                    if item["timestamp"] >= window_start
                    and item["timestamp"] <= event["timestamp"]
                ]

                if len(window_events) < rule.threshold:
                    continue

                if rule.rule_id == "DET-SSH-002":
                    unique_usernames = {
                        item.get("username")
                        for item in window_events
                        if item.get("username")
                    }

                    if len(unique_usernames) < 2:
                        continue

                alerts.append(
                    {
                        "rule_id": rule.rule_id,
                        "rule_name": rule.name,
                        "description": rule.description,
                        "severity": rule.severity,
                        "mitre_technique": rule.mitre_technique,
                        "mitre_tactic": rule.mitre_tactic,
                        "source_ip": source_ip,
                        "event_count": len(window_events),
                        "timestamp": event["timestamp"],
                        "events": window_events,
                    }
                )

                break

        return alerts