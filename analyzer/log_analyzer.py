import re

from pathlib import Path
from dotenv import load_dotenv
import os

BASE_DIR = Path(__file__).parent.parent

load_dotenv(BASE_DIR / ".env")

LOG_FILE = BASE_DIR / "logs" / "auth.log"
FAILED_ATTEMPT_THRESHOLD = int(os.getenv("FAILED_ATTEMPT_THRESHOLD", "3"))


def analyze_logs():
    alerts = []
    failed_attempts = {}
    successful_logins = []
    last_event_time = {}

    with open(LOG_FILE, "r") as file:
        for line in file:
            failed_match = re.search(
                r"Failed password for (\w+) from ([\d.]+)",
                line
            )

            if failed_match:
                username = failed_match.group(1)
                ip_address = failed_match.group(2)

                key = (username, ip_address)

                failed_attempts[key] = failed_attempts.get(key, 0) + 1
                last_event_time[key] = line[:15]

            success_match = re.search(
                r"Accepted password for (\w+) from ([\d.]+)",
                line
            )

            if success_match:
                username = success_match.group(1)
                ip_address = success_match.group(2)

                successful_logins.append(
                    (username, ip_address)
                )

    print("=== SENTINELAI LOG ANALYSIS ===")
    print()

    for (username, ip), attempts in failed_attempts.items():
        print(f"User: {username}")
        print(f"IP: {ip}")
        print(f"Failed attempts: {attempts}")

        successful = (username, ip) in successful_logins

        print(f"Successful login: {'YES' if successful else 'NO'}")

        if attempts >= FAILED_ATTEMPT_THRESHOLD and successful:
            risk = "HIGH"
        elif attempts >= FAILED_ATTEMPT_THRESHOLD:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        print(f"Risk: {risk}")

        if risk in ["HIGH", "MEDIUM"]:
            alerts.append({
               "type": "SSH Brute Force",
               "timestamp": last_event_time[(username, ip)],
                "username": username,
                "ip": ip,
                "failed_attempts": attempts,
                "successful_login": successful,
                "risk": risk
            })

        print()
    print("=== SECURITY ALERTS ===")

    for alert in alerts:
        print(f"[{alert['risk']}] {alert['type']}")
        print(f"Time: {alert['timestamp']}")
        print(f"User: {alert['username']}")
        print(f"Source IP: {alert['ip']}")
        print(f"Failed attempts: {alert['failed_attempts']}")
        print(f"Successful login: {alert['successful_login']}")
        print()

    return alerts    

if __name__ == "__main__":
    analyze_logs()