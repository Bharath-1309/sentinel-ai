class MitreMapper:

    TECHNIQUE_MAP = {
        "SSH Brute Force": {
            "technique_id": "T1110",
            "technique": "Brute Force",
            "tactic": "Credential Access"
        },
        "SSH Password Spraying": {
            "technique_id": "T1110.003",
            "technique": "Password Spraying",
            "tactic": "Credential Access"
        },
        "Suspicious PowerShell": {
            "technique_id": "T1059.001",
            "technique": "PowerShell",
            "tactic": "Execution"
        },
    }


    def map_alert(self, alert):
        mapping = self.TECHNIQUE_MAP.get(
            alert["type"],
            {
                "technique_id": "UNKNOWN",
                "technique": "Unknown",
                "tactic": "Unknown"
            }
        )

        alert.mitre = mapping

        return alert