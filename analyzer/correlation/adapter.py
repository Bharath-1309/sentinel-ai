def detection_alert_to_correlation_alert(alert):
    return {
        "type": alert["rule_name"],
        "ip": alert["source_ip"],
        "risk": alert["severity"],
        "rule_id": alert["rule_id"],
        "event_count": alert["event_count"],
        "timestamp": alert["timestamp"],
        "events": alert["events"],
    }


def detection_alerts_to_correlation_alerts(alerts):
    return [
        detection_alert_to_correlation_alert(alert)
        for alert in alerts
    ]


def existing_alerts_to_correlation_alerts(alerts):
    correlation_alerts = []

    for alert in alerts:
        normalized = {
            "type": alert["type"],
            "ip": alert["ip"],
            "risk": alert["risk"],
            "successful_login": getattr(
                alert, "successful_login", False
            ),
        }

        correlation_alerts.append(normalized)

        if normalized["successful_login"] is True:
            successful_login = dict(normalized)
            successful_login["type"] = "Successful Login"
            correlation_alerts.append(successful_login)

    return correlation_alerts