from .rule_definitions import CORRELATION_RULES
from .models import CorrelationResult


class AdvancedCorrelationEngine:

    def __init__(self, rules=None):
        self.rules = rules or CORRELATION_RULES

    def correlate(self, alerts):
        results = []
        seen_correlations = set()

        for rule in self.rules:
            if not rule.enabled:
                continue

            for source_ip in self._source_ips(alerts):
                source_alerts = [
                    alert
                    for alert in alerts
                    if alert.get("ip") == source_ip
                    or alert.get("source_ip") == source_ip
                ]

                alert_types = {
                    alert.get("type")
                    for alert in source_alerts
                }

                if not rule.required_alert_types.issubset(alert_types):
                    continue

                if rule.correlation_id == "CORR-001":
                    if not self._occurred_in_order(
                        source_alerts,
                        "Network Service Scanning",
                        "SSH Brute Force",
                    ):
                        continue

                if rule.correlation_id == "CORR-002":
                    if not self._occurred_in_order(
                        source_alerts,
                        "SSH Brute Force",
                        "Successful Login",
                    ):
                        continue

                required_alerts = [
                    alert
                    for alert in source_alerts
                    if alert.get("type") in rule.required_alert_types
                ]

                if not self._within_window(
                    required_alerts,
                    rule.window_minutes,
                ):
                    continue

                correlation_key = (
                    rule.correlation_id,
                    source_ip,
                )

                if correlation_key in seen_correlations:
                    continue

                seen_correlations.add(correlation_key)

                results.append(
                    CorrelationResult(
                        correlation_id=rule.correlation_id,
                        name=rule.name,
                        description=rule.description,
                        source_ip=source_ip,
                        severity=rule.severity,
                        alert_count=len(source_alerts),
                        alerts=source_alerts,
                    )
                )

        return results

    @staticmethod
    def _occurred_in_order(source_alerts, first_type, second_type):
        first_positions = []
        second_positions = []

        for index, alert in enumerate(source_alerts):
            timestamp = alert.get("timestamp")

            if timestamp is None:
                for event in alert.get("events", []):
                    event_timestamp = event.get("timestamp")
                    if event_timestamp is not None:
                        timestamp = event_timestamp
                        break

            if alert.get("type") == first_type:
                first_positions.append(
                    (timestamp, index)
                )

            if alert.get("type") == second_type:
                second_positions.append(
                    (timestamp, index)
                )

        if not first_positions or not second_positions:
            return False

        first_time, first_index = min(
            first_positions,
            key=lambda item: (
                item[0] is None,
                item[0] if item[0] is not None else item[1],
            ),
        )

        second_time, second_index = min(
            second_positions,
            key=lambda item: (
                item[0] is None,
                item[0] if item[0] is not None else item[1],
            ),
        )

        if first_time is not None and second_time is not None:
            return first_time < second_time

        return first_index < second_index


    @staticmethod
    def _within_window(source_alerts, window_minutes):
        timestamps = []

        for alert in source_alerts:
            timestamp = alert.get("timestamp")

            if timestamp is None:
                for event in alert.get("events", []):
                    timestamp = event.get("timestamp")
                    if timestamp is not None:
                        break

            if timestamp is not None:
                timestamps.append(timestamp)

        if len(timestamps) < 2:
            return True

        earliest = min(timestamps)
        latest = max(timestamps)

        return (latest - earliest).total_seconds() <= (
            window_minutes * 60
        )


    @staticmethod
    def _source_ips(alerts):
        return {
            alert.get("ip") or alert.get("source_ip")
            for alert in alerts
            if alert.get("ip") or alert.get("source_ip")
        }