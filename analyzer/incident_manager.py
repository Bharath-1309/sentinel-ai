from datetime import datetime


class IncidentManager:

    def create_incident(self, correlation):
        alerts = correlation["alerts"]

        timestamps = [
            alert["timestamp"]
            for alert in alerts
            if alert["timestamp"] is not None
        ]

        start_time = min(timestamps) if timestamps else None
        end_time = max(timestamps) if timestamps else None

        return {
            "incident_id": self._generate_incident_id(start_time),
            "type": correlation["type"],
            "source_ip": correlation["source_ip"],
            "risk": correlation["risk"],
            "alert_count": correlation["alert_count"],
            "start_time": start_time,
            "end_time": end_time,
            "status": "OPEN",
            "evidence": alerts
        }

    @staticmethod
    def _generate_incident_id(timestamp):
        if timestamp is None:
            return "INC-UNKNOWN"

        return f"INC-{timestamp.strftime('%Y%m%d%H%M%S')}"