class RiskEngine:

    def calculate_score(self, alerts):

        score = 0

        for alert in alerts:

            if alert["type"] == "SSH Brute Force":
                score += 30

                if alert["failed_attempts"] >= 5:
                    score += 10

            elif alert["type"] == "SSH Password Spraying":
                score += 40

                if alert["failed_attempts"] >= 5:
                    score += 10

            if alert["successful_login"]:
                score += 40

            if alert["risk"] == "CRITICAL":
                score += 20
            elif alert["risk"] == "HIGH":
                score += 10

        score = min(score, 100)

        return {
            "score": score,
            "risk": self._risk_level(score)
        }

    @staticmethod
    def _risk_level(score):

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 30:
            return "MEDIUM"

        return "LOW"