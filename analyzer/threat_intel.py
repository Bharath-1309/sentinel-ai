import os
import requests


class ThreatIntelligence:

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self):
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")

    def lookup_ip(self, ip_address):

        if not self.api_key:
            return {
                "ip": ip_address,
                "malicious": False,
                "threat": None,
                "confidence": 0,
                "source": "AbuseIPDB"
            }

        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }

        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90
        }

        try:
            response = requests.get(
                self.API_URL,
                headers=headers,
                params=params,
                timeout=5
            )

            if response.status_code != 200:
                return None

            data = response.json()["data"]

            confidence = data.get(
                "abuseConfidenceScore",
                0
            )

            return {
                "ip": ip_address,
                "malicious": confidence > 0,
                "threat": (
                    "Reported Malicious IP"
                    if confidence > 0
                    else None
                ),
                "confidence": confidence,
                "source": "AbuseIPDB"
            }

        except Exception:
            return {
                "ip": ip_address,
                "malicious": False,
                "threat": None,
                "confidence": 0,
                "source": "AbuseIPDB (unavailable)"
            }