class AISOCAgent:

    def investigate(self, incident):
        """
        Investigate a security incident and generate
        a deterministic SOC investigation summary.
        """

        risk = incident["risk"]
        incident_type = incident["type"]

        if risk == "CRITICAL":
            analysis = (
                f"The incident '{incident_type}' is classified as "
                "critical and requires immediate investigation."
            )

            recommendations = [
                "Review the affected account activity.",
                "Validate the source IP against security logs.",
                "Check for additional successful authentication events.",
                "Consider temporarily blocking the source IP if malicious activity is confirmed."
            ]

        elif risk == "HIGH":
            analysis = (
                f"The incident '{incident_type}' is classified as "
                "high risk and requires investigation."
            )

            recommendations = [
                "Review authentication activity from the source IP.",
                "Check for repeated credential attacks.",
                "Investigate affected user accounts."
            ]

        else:
            analysis = (
                f"The incident '{incident_type}' requires security "
                "investigation based on the detected activity."
            )

            recommendations = [
                "Review the related security logs.",
                "Monitor the source IP for additional suspicious activity."
            ]

        return {
            "incident_id": incident["incident_id"],
            "type": incident_type,
            "risk": risk,
            "source_ip": incident["source_ip"],
            "investigation_status": "COMPLETED",
            "analysis": analysis,
            "recommendations": recommendations
        }