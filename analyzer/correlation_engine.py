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

            has_windows_brute_force = (
                "Windows Authentication Brute Force"
                in alert_types
            )

            has_windows_password_spraying = (
                "Windows Password Spraying"
                in alert_types
            )

            has_network_scan = (
                "Network Service Scanning"
                in alert_types
            )

            has_credential_dumping = (
                "Credential Dumping"
                in alert_types
            )

            has_powershell = (
                "Suspicious PowerShell"
                in alert_types
            )

            # Existing SSH correlation logic
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
                    (
                        alert["risk"]
                        for alert in ip_alerts
                    ),
                    key=self._risk_score
                )

            # Windows authentication attacks
            elif (
                has_windows_brute_force
                and has_windows_password_spraying
            ):
                incident_type = "Coordinated Windows Credential Attack"
                risk = "CRITICAL"

            elif has_windows_password_spraying:
                incident_type = "Windows Credential Attack"
                risk = "HIGH"

            elif has_windows_brute_force:
                incident_type = "Windows Authentication Attack"
                risk = max(
                    (
                        alert["risk"]
                        for alert in ip_alerts
                    ),
                    key=self._risk_score
                )

            # Discovery + credential access
            elif (
                has_network_scan
                and has_credential_dumping
            ):
                incident_type = "Potential Host Compromise"
                risk = "CRITICAL"

            elif has_network_scan:
                incident_type = "Network Reconnaissance"
                risk = "HIGH"

            elif has_credential_dumping:
                incident_type = "Credential Theft Activity"
                risk = "CRITICAL"

            # PowerShell execution
            elif has_powershell:
                incident_type = "Suspicious PowerShell Activity"
                risk = "HIGH"

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