import re
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

from analyzer.mitre_mapper import MitreMapper
from analyzer.threat_intel import ThreatIntelligence
from analyzer.ai_agent import AISOCAgent
from analyzer.windows_auth_detector import WindowsAuthDetector
from analyzer.windows_password_spray_detector import (
    WindowsPasswordSprayDetector,
)
from analyzer.network_scan_detector import NetworkScanDetector
from analyzer.credential_dumping_detector import CredentialDumpingDetector
from analyzer.response_engine import ResponseEngine
from analyzer.database import initialize_database, save_incident
from analyzer.ingestion.pipeline import LinuxIngestionPipeline
from analyzer.detections.service import DetectionService

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

FAILED_ATTEMPT_THRESHOLD = int(
    os.getenv("FAILED_ATTEMPT_THRESHOLD", "3")
)

ALERT_WINDOW_MINUTES = int(
    os.getenv("ALERT_WINDOW_MINUTES", "5")
)


def parse_timestamp(line):
    timestamp = line[:15]

    return datetime.strptime(
        f"{datetime.now().year} {timestamp}",
        "%Y %b %d %H:%M:%S",
    )


def parse_network_timestamp(line):
    match = re.search(
        r"(\d{4} \w{3} \d{2} \d{2}:\d{2}:\d{2})",
        line,
    )

    if not match:
        return None

    return datetime.strptime(
        match.group(1),
        "%Y %b %d %H:%M:%S",
    )


def parse_windows_auth_line(line):
    match = re.search(
        r"(\d{4} \w{3} \d{2} \d{2}:\d{2}:\d{2}) "
        r"Failed Windows login for (\w+) from ([\d.]+)",
        line,
    )

    if not match:
        return None

    timestamp = datetime.strptime(
        match.group(1),
        "%Y %b %d %H:%M:%S",
    )

    return {
        "username": match.group(2),
        "ip": match.group(3),
        "timestamp": timestamp,
    }


def analyze_logs(log_file=LOG_FILE):

    initialize_database()

    alerts = []

    detection_engine = DetectionEngine()
    detection_service = DetectionService()
    windows_auth_detector = WindowsAuthDetector()
    windows_password_spray_detector = WindowsPasswordSprayDetector()
    correlation_engine = CorrelationEngine()
    incident_manager = IncidentManager()
    risk_engine = RiskEngine()
    ai_agent = AISOCAgent()
    mitre_mapper = MitreMapper()
    threat_intel = ThreatIntelligence()
    network_scan_detector = NetworkScanDetector()
    credential_dumping_detector = CredentialDumpingDetector()
    response_engine = ResponseEngine()

    failed_attempts = {}
    successful_logins = []

    suspicious_root_logins = []

    password_spray_attempts = {}

    windows_failed_attempts = {}
    windows_password_spray_attempts = {}

    network_scan_attempts = {}
    credential_dumping_attempts = {}

    # ---------------------------------------------------------
    # NEW INGESTION LAYER
    # ---------------------------------------------------------

    linux_pipeline = LinuxIngestionPipeline()

    normalized_events = linux_pipeline.ingest(log_file)
    detection_alerts = detection_service.detect(normalized_events)

    # Convert normalized Linux events into the structures
    # required by the existing detection engine.
    for event in normalized_events:

        event_type = event["event_type"]
        username = event["username"]
        ip_address = event["ip"]
        timestamp = event["timestamp"]

        # ---------------------------------------------
        # SSH AUTHENTICATION FAILURE
        # ---------------------------------------------

        if event_type == "authentication_failure":

            key = (username, ip_address)

            if ip_address not in password_spray_attempts:
                password_spray_attempts[ip_address] = {
                    "usernames": set(),
                    "last_timestamp": timestamp,
                }

            password_spray_attempts[ip_address][
                "usernames"
            ].add(username)

            password_spray_attempts[ip_address][
                "last_timestamp"
            ] = timestamp

            if key not in failed_attempts:
                failed_attempts[key] = []

            failed_attempts[key].append(timestamp)

        # ---------------------------------------------
        # SSH AUTHENTICATION SUCCESS
        # ---------------------------------------------

        elif event_type == "authentication_success":

            successful_logins.append(
                (username, ip_address)
            )

            if username == "root":

                suspicious_root_logins.append(
                    {
                        "username": username,
                        "ip": ip_address,
                        "timestamp": timestamp,
                    }
                )

    # ---------------------------------------------------------
    # EXISTING SECONDARY LOG SOURCES
    #
    # These remain temporarily in the existing raw-log format.
    # They will be migrated to the common SecurityEvent model
    # in the next ingestion stages.
    # ---------------------------------------------------------

    with open(
        log_file,
        "r",
        encoding="utf-8",
        errors="replace",
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            # ---------------------------------------------
            # WINDOWS AUTHENTICATION
            # ---------------------------------------------

            windows_event = parse_windows_auth_line(line)

            if windows_event:

                key = (
                    windows_event["username"],
                    windows_event["ip"],
                )

                if key not in windows_failed_attempts:
                    windows_failed_attempts[key] = []

                windows_failed_attempts[key].append(
                    windows_event["timestamp"]
                )

                if (
                    windows_event["ip"]
                    not in windows_password_spray_attempts
                ):

                    windows_password_spray_attempts[
                        windows_event["ip"]
                    ] = {
                        "usernames": set(),
                        "last_timestamp": windows_event[
                            "timestamp"
                        ],
                    }

                windows_password_spray_attempts[
                    windows_event["ip"]
                ]["usernames"].add(
                    windows_event["username"]
                )

                windows_password_spray_attempts[
                    windows_event["ip"]
                ]["last_timestamp"] = (
                    windows_event["timestamp"]
                )

            # ---------------------------------------------
            # NETWORK SERVICE SCANNING
            # ---------------------------------------------

            network_match = re.search(
                r"Connection attempt from ([\d.]+) to port (\d+)",
                line,
            )

            if network_match:

                ip_address = network_match.group(1)
                port = int(network_match.group(2))

                timestamp = parse_network_timestamp(line)

                if ip_address not in network_scan_attempts:

                    network_scan_attempts[ip_address] = {
                        "ports": set(),
                        "last_timestamp": timestamp,
                    }

                network_scan_attempts[
                    ip_address
                ]["ports"].add(port)

                network_scan_attempts[
                    ip_address
                ]["last_timestamp"] = timestamp

            # ---------------------------------------------
            # CREDENTIAL DUMPING
            # ---------------------------------------------

            credential_match = re.search(
                r"Process lsass\.exe accessed by suspicious process "
                r"procdump\.exe from ([\d.]+)",
                line,
            )

            if credential_match:

                ip_address = credential_match.group(1)

                timestamp = parse_network_timestamp(line)

                if (
                    ip_address
                    not in credential_dumping_attempts
                ):

                    credential_dumping_attempts[
                        ip_address
                    ] = {
                        "count": 0,
                        "username": None,
                        "last_timestamp": timestamp,
                    }

                credential_dumping_attempts[
                    ip_address
                ]["count"] += 1

                credential_dumping_attempts[
                    ip_address
                ]["last_timestamp"] = timestamp

            credential_match = re.search(
                r"Credential dumping activity detected from "
                r"([\d.]+) for (\w+)",
                line,
            )

            if credential_match:

                ip_address = credential_match.group(1)
                username = credential_match.group(2)

                timestamp = parse_network_timestamp(line)

                if (
                    ip_address
                    not in credential_dumping_attempts
                ):

                    credential_dumping_attempts[
                        ip_address
                    ] = {
                        "count": 0,
                        "username": username,
                        "last_timestamp": timestamp,
                    }

                credential_dumping_attempts[
                    ip_address
                ]["count"] += 1

                credential_dumping_attempts[
                    ip_address
                ]["username"] = username

                credential_dumping_attempts[
                    ip_address
                ]["last_timestamp"] = timestamp

    # ---------------------------------------------------------
    # DETECTION ENGINE
    # ---------------------------------------------------------

    print("=== SENTINELAI LOG ANALYSIS ===")
    print()

    for (username, ip), timestamps in failed_attempts.items():

        alert = detection_engine.detect_brute_force(
            username=username,
            ip_address=ip,
            timestamps=timestamps,
            threshold=FAILED_ATTEMPT_THRESHOLD,
            window_minutes=ALERT_WINDOW_MINUTES,
            successful_login=(username, ip)
            in successful_logins,
        )

        attempts = (
            alert["failed_attempts"]
            if alert
            else 0
        )

        print(f"User: {username}")
        print(f"IP: {ip}")
        print(f"Failed attempts: {attempts}")

        successful = (
            username,
            ip,
        ) in successful_logins

        print(
            f"Successful login: "
            f"{'YES' if successful else 'NO'}"
        )

        if alert:
            risk = alert["risk"]
        else:
            risk = "LOW"

        print(f"Risk: {risk}")

        if alert:
            alerts.append(alert)

    # ---------------------------------------------------------
    # WINDOWS AUTHENTICATION BRUTE FORCE
    # ---------------------------------------------------------

    for (
        username,
        ip_address,
    ), timestamps in windows_failed_attempts.items():

        alert = windows_auth_detector.detect_brute_force(
            username=username,
            source_ip=ip_address,
            failed_attempts=len(timestamps),
            timestamp=timestamps[-1],
            threshold=FAILED_ATTEMPT_THRESHOLD,
        )

        if alert:
            alerts.append(alert)

    # ---------------------------------------------------------
    # WINDOWS PASSWORD SPRAYING
    # ---------------------------------------------------------

    for (
        ip_address,
        spray_data,
    ) in windows_password_spray_attempts.items():

        alert = windows_password_spray_detector.detect(
            source_ip=ip_address,
            username_attempts=spray_data["usernames"],
            timestamp=spray_data["last_timestamp"],
            threshold=3,
        )

        if alert:
            alerts.append(alert)

    # ---------------------------------------------------------
    # NETWORK SERVICE SCANNING
    # ---------------------------------------------------------

    for (
        ip_address,
        scan_data,
    ) in network_scan_attempts.items():

        alert = network_scan_detector.detect(
            source_ip=ip_address,
            target_ports=scan_data["ports"],
            timestamp=scan_data["last_timestamp"],
            threshold=5,
        )

        if alert:
            alerts.append(alert)

    # ---------------------------------------------------------
    # CREDENTIAL DUMPING
    # ---------------------------------------------------------

    for (
        ip_address,
        dump_data,
    ) in credential_dumping_attempts.items():

        alert = credential_dumping_detector.detect(
            source_ip=ip_address,
            evidence_count=dump_data["count"],
            timestamp=dump_data["last_timestamp"],
            username=dump_data["username"],
            threshold=1,
        )

        if alert:
            alerts.append(alert)

    # ---------------------------------------------------------
    # SSH PASSWORD SPRAYING
    # ---------------------------------------------------------

    print()

    for (
        ip_address,
        spray_data,
    ) in password_spray_attempts.items():

        alert = detection_engine.detect_password_spraying(
            ip_address=ip_address,
            username_attempts=spray_data["usernames"],
            threshold=3,
            timestamp=spray_data["last_timestamp"],
        )

        if alert:
            alerts.append(alert) 

    # ---------------------------------------------------------
    # MITRE ATT&CK
    # ---------------------------------------------------------

    alerts = [
        mitre_mapper.map_alert(alert)
        for alert in alerts
    ]

    # ---------------------------------------------------------
    # THREAT INTELLIGENCE
    # ---------------------------------------------------------

    for alert in alerts:

        alert.threat_intelligence = (
            threat_intel.lookup_ip(
                alert["ip"]
            )
        )

    # ---------------------------------------------------------
    # CORRELATION
    # ---------------------------------------------------------

    correlations = correlation_engine.correlate(
        alerts
    )

    incidents = []

    # ---------------------------------------------------------
    # INCIDENT CREATION
    # ---------------------------------------------------------

    for correlation in correlations:

        incident = incident_manager.create_incident(
            correlation
        )

        risk_result = risk_engine.calculate_score(
            correlation["alerts"]
        )

        incident["risk_score"] = risk_result["score"]
        incident["risk"] = risk_result["risk"]

        incidents.append(incident)

        # -----------------------------------------------------
        # AI INVESTIGATION
        # -----------------------------------------------------

        incident["ai_investigation"] = (
            ai_agent.investigate(incident)
        )

        # -----------------------------------------------------
        # RESPONSE PLAYBOOK
        # -----------------------------------------------------

        incident["response_playbook"] = (
            response_engine.generate_playbook(
                incident
            )
        )

        # -----------------------------------------------------
        # DATABASE
        # -----------------------------------------------------

        save_incident(incident)

    # ---------------------------------------------------------
    # INCIDENT OUTPUT
    # ---------------------------------------------------------

    print("\n=== SECURITY INCIDENTS ===")

    for incident in incidents:

        print(
            f"[{incident['risk']}] "
            f"{incident['type']}"
        )

        print(
            f"Incident ID: "
            f"{incident['incident_id']}"
        )

        print(
            f"Source IP: "
            f"{incident['source_ip']}"
        )

        print(
            f"Risk Score: "
            f"{incident['risk_score']}/100"
        )

        print(
            f"Status: "
            f"{incident['status']}"
        )

        print(
            f"Alerts Correlated: "
            f"{incident['alert_count']}"
        )

        print("MITRE ATT&CK:")

        for technique in incident[
            "mitre_techniques"
        ]:

            print(
                f"  {technique['technique_id']} - "
                f"{technique['technique']} "
                f"({technique['tactic']})"
            )

        print(
            f"Start: "
            f"{incident['start_time']}"
        )

        print(
            f"End: "
            f"{incident['end_time']}"
        )

        print(
            "Recommended Response Actions:"
        )

        for action in incident[
            "response_playbook"
        ]["actions"]:

            print(f"  - {action}")

        print()

    # ---------------------------------------------------------
    # SUSPICIOUS ROOT LOGINS
    # ---------------------------------------------------------

    print("\n=== SUSPICIOUS ROOT LOGINS ===")

    for login in suspicious_root_logins:

        print(
            f"Time: "
            f"{login['timestamp']}"
        )

        print(
            f"User: "
            f"{login['username']}"
        )

        print(
            f"Source IP: "
            f"{login['ip']}"
        )

    # ---------------------------------------------------------
    # SECURITY ALERTS
    # ---------------------------------------------------------

    print("=== SECURITY ALERTS ===")

    for alert in alerts:

        print(
            f"[{alert['risk']}] "
            f"{alert['type']}"
        )

        print(
            f"Time: "
            f"{alert['timestamp']}"
        )

        print(
            f"User: "
            f"{alert['username']}"
        )

        print(
            f"Source IP: "
            f"{alert['ip']}"
        )

        print(
            f"Failed attempts: "
            f"{alert['failed_attempts']}"
        )

        print(
            f"Successful login: "
            f"{alert['successful_login']}"
        )

        print(
            f"MITRE Technique: "
            f"{alert['mitre']['technique_id']} - "
            f"{alert['mitre']['technique']}"
        )

        print(
            f"MITRE Tactic: "
            f"{alert['mitre']['tactic']}"
        )

        ti = alert["threat_intelligence"]

        print("Threat Intelligence:")

        print(
            f"  Malicious: "
            f"{'YES' if ti['malicious'] else 'NO'}"
        )

        print(
            f"  Threat: "
            f"{ti['threat'] or 'None'}"
        )

        print(
            f"  Confidence: "
            f"{ti['confidence']}%"
        )

        print(
            f"  Source: "
            f"{ti['source']}"
        )

        print()

    return {
        "alerts": alerts,
        "incidents": incidents,
    }


if __name__ == "__main__":
    analyze_logs()