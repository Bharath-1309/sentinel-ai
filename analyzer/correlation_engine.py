from collections import defaultdict


class CorrelationEngine:

    def correlate(self, alerts):
        incidents = []

        alerts_by_ip = defaultdict(list)

        for alert in alerts:
            alerts_by_ip[alert["ip"]].append(alert)

        for ip_address, ip_alerts in alerts_by_ip.items():

            alert_types = {
                alert["type"]
                for alert in ip_alerts
            }

            has_brute_force = "SSH Brute Force" in alert_types
            has_password_spraying = "SSH Password Spraying" in alert_types
            has_successful_login = any(
                alert["successful_login"]
                for alert in ip_alerts
            )

            if (
                has_brute_force
                and has_successful_login
            ):
                incident_type = "Potential Account Compromise"
                risk = "CRITICAL"

            elif (
                has_brute_force
                and has_password_spraying
            ):
                incident_type = "Coordinated SSH Attack"
                risk = "CRITICAL"

            elif has_password_spraying:
                incident_type = "SSH Credential Attack"
                risk = "HIGH"

            elif has_brute_force:
                incident_type = "SSH Brute Force Incident"
                risk = max(
                    (alert["risk"] for alert in ip_alerts),
                    key=self._risk_score
                )

            else:
                continue

            incidents.append({
                "type": incident_type,
                "source_ip": ip_address,
                "risk": risk,
                "alert_count": len(ip_alerts),
                "alerts": ip_alerts
            })

        return incidents

    @staticmethod
    def _risk_score(risk):
        scores = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }

        return scores.get(risk, 0)