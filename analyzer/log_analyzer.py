import re

from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from analyzer.mitre_mapper import MitreMapper
from analyzer.threat_intel import ThreatIntelligence

try:
    from analyzer.detection_engine import DetectionEngine
    from analyzer.correlation_engine import CorrelationEngine
    from analyzer.incident_manager import IncidentManager
    from analyzer.risk_engine import RiskEngine
except ModuleNotFoundError:
    from detection_engine import DetectionEngine
    from correlation_engine import CorrelationEngine
    from incident_manager import IncidentManager
    from risk_engine import RiskEngine
import os

BASE_DIR = Path(__file__).parent.parent

load_dotenv(BASE_DIR / ".env")

LOG_FILE = BASE_DIR / "logs" / "auth.log"
FAILED_ATTEMPT_THRESHOLD = int(os.getenv("FAILED_ATTEMPT_THRESHOLD", "3"))
ALERT_WINDOW_MINUTES = int(os.getenv("ALERT_WINDOW_MINUTES", "5"))

def parse_timestamp(line):
    timestamp = line[:15]
    return datetime.strptime(
        f"{datetime.now().year} {timestamp}",
        "%Y %b %d %H:%M:%S"
    )

def analyze_logs(log_file=LOG_FILE):
    alerts = []
    detection_engine = DetectionEngine()
    correlation_engine = CorrelationEngine()
    incident_manager = IncidentManager()
    risk_engine = RiskEngine()
    mitre_mapper = MitreMapper()
    threat_intel = ThreatIntelligence()
    failed_attempts = {}
    successful_logins = []
    suspicious_root_logins = []
    password_spray_attempts = {}

    with open(log_file, "r") as file:
        for line in file:
            failed_match = re.search(
                r"Failed password for (\w+) from ([\d.]+)",
                line
            )

            if failed_match:
                username = failed_match.group(1)
                ip_address = failed_match.group(2)

                key = (username, ip_address)

                timestamp = parse_timestamp(line)

                if ip_address not in password_spray_attempts:
                    password_spray_attempts[ip_address] = {
                       "usernames": set(),
                       "last_timestamp": timestamp
                    }

                password_spray_attempts[ip_address]["usernames"].add(username)
                password_spray_attempts[ip_address]["last_timestamp"] = timestamp

                if key not in failed_attempts:
                   failed_attempts[key] = []

                failed_attempts[key].append(timestamp)

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
                if username == "root":
                    suspicious_root_logins.append({
                        "username": username,
                        "ip": ip_address,
                        "timestamp": parse_timestamp(line)
                    })

    print("=== SENTINELAI LOG ANALYSIS ===")
    print()

    for (username, ip), timestamps in failed_attempts.items():
        alert = detection_engine.detect_brute_force(
            username=username,
            ip_address=ip,
            timestamps=timestamps,
            threshold=FAILED_ATTEMPT_THRESHOLD,
            window_minutes=ALERT_WINDOW_MINUTES,
            successful_login=(username, ip) in successful_logins
        )

        attempts = (
            alert["failed_attempts"]
            if alert
            else 0
        )
        print(f"User: {username}")
        print(f"IP: {ip}")
        print(f"Failed attempts: {attempts}")

        successful = (username, ip) in successful_logins

        print(f"Successful login: {'YES' if successful else 'NO'}")

        if alert:
            risk = alert["risk"]
        else:
            risk = "LOW"

        print(f"Risk: {risk}")

        if alert:
           alerts.append(alert)

    print()
    for ip_address, spray_data in password_spray_attempts.items():
        alert = detection_engine.detect_password_spraying(
            ip_address=ip_address,
            username_attempts=spray_data["usernames"],
            threshold=3,
            timestamp=spray_data["last_timestamp"]
        )

        if alert:
            alerts.append(alert)

        alerts = [
            mitre_mapper.map_alert(alert)
            for alert in alerts
        ]

    for alert in alerts:
        alert.threat_intelligence = threat_intel.lookup_ip(
        alert["ip"]
    )

    correlations = correlation_engine.correlate(alerts)
    incidents = []

    for correlation in correlations:
        incident = incident_manager.create_incident(correlation)

        risk_result = risk_engine.calculate_score(
            correlation["alerts"]
        )

        incident["risk_score"] = risk_result["score"]
        incident["risk"] = risk_result["risk"]

        incidents.append(incident)

    print("\n=== SECURITY INCIDENTS ===")

    for incident in incidents:
        print(f"[{incident['risk']}] {incident['type']}")
        print(f"Incident ID: {incident['incident_id']}")
        print(f"Source IP: {incident['source_ip']}")
        print(f"Risk Score: {incident['risk_score']}/100")
        print(f"Status: {incident['status']}")
        print(f"Alerts Correlated: {incident['alert_count']}")

        print("MITRE ATT&CK:")
        for technique in incident["mitre_techniques"]:
            print(
                f"  {technique['technique_id']} - "
                f"{technique['technique']} "
                f"({technique['tactic']})"
    )

        print(f"Start: {incident['start_time']}")
        print(f"End: {incident['end_time']}")
        print()

    print("\n=== SUSPICIOUS ROOT LOGINS ===")

    for login in suspicious_root_logins:
        print(f"Time: {login['timestamp']}")
        print(f"User: {login['username']}")
        print(f"Source IP: {login['ip']}")

    print("=== SECURITY ALERTS ===")

    for alert in alerts:
        print(f"[{alert['risk']}] {alert['type']}")
        print(f"Time: {alert['timestamp']}")
        print(f"User: {alert['username']}")
        print(f"Source IP: {alert['ip']}")
        print(f"Failed attempts: {alert['failed_attempts']}")
        print(f"Successful login: {alert['successful_login']}")
        print(f"MITRE Technique: {alert['mitre']['technique_id']} - {alert['mitre']['technique']}")
        print(f"MITRE Tactic: {alert['mitre']['tactic']}")
        ti = alert["threat_intelligence"]

        print(f"Threat Intelligence:")
        print(f"  Malicious: {'YES' if ti['malicious'] else 'NO'}")
        print(f"  Threat: {ti['threat'] or 'None'}")
        print(f"  Confidence: {ti['confidence']}%")
        print(f"  Source: {ti['source']}")
        print()

    return {
        "alerts": alerts,
        "incidents": incidents
    }

if __name__ == "__main__":
    analyze_logs()