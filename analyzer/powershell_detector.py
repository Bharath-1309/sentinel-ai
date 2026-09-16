import re


class PowerShellDetector:

    SUSPICIOUS_PATTERNS = [
        r"-enc(?:odedcommand)?\b",
        r"frombase64string",
        r"invoke-expression",
        r"\biex\b",
        r"downloadstring",
        r"invoke-webrequest",
        r"\biwr\b",
        r"start-bitstransfer",
        r"hidden",
        r"bypass",
        r"executionpolicy\s+bypass",
    ]

    def analyze(self, command):

        if not isinstance(command, str):
            raise TypeError("command must be a string")

        command_lower = command.lower()

        matched_patterns = [
            pattern
            for pattern in self.SUSPICIOUS_PATTERNS
            if re.search(pattern, command_lower)
        ]

        risk_score = min(
            len(matched_patterns) * 20,
            100
        )

        if risk_score >= 60:
            risk = "CRITICAL"
        elif risk_score >= 40:
            risk = "HIGH"
        elif risk_score >= 20:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        return {
            "is_suspicious": bool(matched_patterns),
            "risk": risk,
            "risk_score": risk_score,
            "matched_patterns": matched_patterns
        }