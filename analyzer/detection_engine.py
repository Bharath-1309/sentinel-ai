from datetime import timedelta


class DetectionEngine:

    def detect_brute_force(
        self,
        username,
        ip_address,
        timestamps,
        threshold,
        window_minutes,
        successful_login=False
    ):
        if not timestamps:
            return None

        window_start = timestamps[-1] - timedelta(minutes=window_minutes)

        recent_attempts = [
            timestamp
            for timestamp in timestamps
            if timestamp >= window_start
        ]

        if len(recent_attempts) < threshold:
            return None

        risk = "CRITICAL" if successful_login else "MEDIUM"

        return {
            "type": "SSH Brute Force",
            "timestamp": timestamps[-1],
            "username": username,
            "ip": ip_address,
            "failed_attempts": len(recent_attempts),
            "successful_login": successful_login,
            "risk": risk
        }