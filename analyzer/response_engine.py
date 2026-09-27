class ResponseEngine:

    PLAYBOOKS = {
        "Credential Theft Activity": {
            "severity": "CRITICAL",
            "actions": [
                "Isolate the affected endpoint",
                "Reset potentially compromised credentials",
                "Investigate LSASS access activity",
                "Collect endpoint forensic evidence",
                "Search for persistence mechanisms",
                "Review lateral movement activity",
                "Preserve relevant security logs"
            ]
        },

        "Potential Host Compromise": {
            "severity": "CRITICAL",
            "actions": [
                "Isolate the affected endpoint",
                "Investigate the source IP",
                "Review discovered services",
                "Investigate credential access activity",
                "Search for persistence mechanisms",
                "Review lateral movement indicators",
                "Preserve forensic evidence"
            ]
        },

        "Network Reconnaissance": {
            "severity": "HIGH",
            "actions": [
                "Investigate the scanning source IP",
                "Review targeted ports and services",
                "Check for subsequent exploitation attempts",
                "Review network security logs",
                "Monitor the source for additional activity"
            ]
        },

        "SSH Credential Attack": {
            "severity": "HIGH",
            "actions": [
                "Block or investigate the source IP",
                "Review targeted accounts",
                "Reset potentially compromised credentials",
                "Enable or verify MFA",
                "Review authentication logs"
            ]
        },

        "Windows Credential Attack": {
            "severity": "HIGH",
            "actions": [
                "Investigate the source IP",
                "Review targeted Windows accounts",
                "Reset potentially compromised credentials",
                "Verify MFA and account protections",
                "Review Windows authentication logs"
            ]
        },

        "Suspicious PowerShell Activity": {
            "severity": "HIGH",
            "actions": [
                "Investigate the PowerShell command",
                "Identify the initiating process",
                "Review the affected endpoint",
                "Search for persistence mechanisms",
                "Check for command-and-control activity"
            ]
        }
    }

    def generate_playbook(self, incident):
        incident_type = incident["type"]

        playbook = self.PLAYBOOKS.get(
            incident_type,
            {
                "severity": incident["risk"],
                "actions": [
                    "Investigate the incident",
                    "Review related security logs",
                    "Identify affected systems",
                    "Preserve relevant evidence",
                    "Monitor for additional suspicious activity"
                ]
            }
        )

        return {
            "incident_id": incident["incident_id"],
            "incident_type": incident_type,
            "severity": playbook["severity"],
            "actions": playbook["actions"]
        }