import ast
import json
import re
import sqlite3
from dataclasses import asdict, is_dataclass
from pathlib import Path


DATABASE_PATH = Path("sentinelai.db")


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def serialize_value(value):
    """
    Convert dataclasses and datetime values into JSON-serializable
    Python objects.
    """

    if is_dataclass(value):
        return serialize_value(asdict(value))

    if isinstance(value, dict):
        return {
            key: serialize_value(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            serialize_value(item)
            for item in value
        ]

    if isinstance(value, tuple):
        return [
            serialize_value(item)
            for item in value
        ]

    if hasattr(value, "isoformat"):
        return value.isoformat()

    return value


def parse_legacy_evidence(value):
    """
    Convert old stringified dataclass evidence into dictionaries.

    Example old format:

    CredentialDumpingAlert(
        type='Credential Dumping',
        timestamp=datetime.datetime(...),
        username='administrator',
        ip='192.168.1.80',
        ...
    )
    """

    if not isinstance(value, str):
        return value

    # Already JSON/object-like
    if not value.endswith(")") or "(" not in value:
        return value

    match = re.match(
        r"^([A-Za-z0-9_]+)\((.*)\)$",
        value,
        re.DOTALL,
    )

    if not match:
        return value

    alert_class = match.group(1)
    content = match.group(2)

    result = {}

    # ------------------------------------------------------------
    # type
    # ------------------------------------------------------------

    type_match = re.search(
        r"type='([^']*)'",
        content,
    )

    if type_match:
        result["type"] = type_match.group(1)

    # ------------------------------------------------------------
    # timestamp
    # ------------------------------------------------------------

    timestamp_match = re.search(
        r"timestamp=datetime\.datetime\(([^)]*)\)",
        content,
    )

    if timestamp_match:

        parts = [
            int(part.strip())
            for part in timestamp_match.group(1).split(",")
            if part.strip()
        ]

        if len(parts) >= 3:

            year = parts[0]
            month = parts[1]
            day = parts[2]

            hour = parts[3] if len(parts) > 3 else 0
            minute = parts[4] if len(parts) > 4 else 0
            second = parts[5] if len(parts) > 5 else 0

            result["timestamp"] = (
                f"{year:04d}-{month:02d}-{day:02d}"
                f"T{hour:02d}:{minute:02d}:{second:02d}"
            )

    # ------------------------------------------------------------
    # username
    # ------------------------------------------------------------

    username_match = re.search(
        r"username='([^']*)'",
        content,
    )

    if username_match:
        result["username"] = username_match.group(1)

    elif "username=None" in content:
        result["username"] = None

    # ------------------------------------------------------------
    # ip
    # ------------------------------------------------------------

    ip_match = re.search(
        r"ip='([^']*)'",
        content,
    )

    if ip_match:
        result["ip"] = ip_match.group(1)

    # ------------------------------------------------------------
    # failed_attempts
    # ------------------------------------------------------------

    failed_match = re.search(
        r"failed_attempts=(\d+)",
        content,
    )

    if failed_match:
        result["failed_attempts"] = int(
            failed_match.group(1)
        )

    # ------------------------------------------------------------
    # successful_login
    # ------------------------------------------------------------

    success_match = re.search(
        r"successful_login=(True|False)",
        content,
    )

    if success_match:
        result["successful_login"] = (
            success_match.group(1) == "True"
        )

    # ------------------------------------------------------------
    # risk
    # ------------------------------------------------------------

    risk_match = re.search(
        r"risk='([^']*)'",
        content,
    )

    if risk_match:
        result["risk"] = risk_match.group(1)

    # ------------------------------------------------------------
    # MITRE technique
    # ------------------------------------------------------------

    mitre_match = re.search(
        r"mitre=\{([^}]*)\}",
        content,
    )

    if mitre_match:

        mitre_text = "{" + mitre_match.group(1) + "}"

        try:
            result["mitre"] = ast.literal_eval(
                mitre_text
            )
        except (ValueError, SyntaxError):
            pass

    # ------------------------------------------------------------
    # Preserve class name for debugging if parsing was incomplete
    # ------------------------------------------------------------

    if not result:
        return value

    # Some older detectors don't have all fields.
    # Keep the detector type internally useful without
    # changing the displayed incident type.
    result["_legacy_alert_class"] = alert_class

    return result


def normalize_evidence(evidence):

    if not isinstance(evidence, list):
        return []

    normalized = []

    for item in evidence:

        if isinstance(item, dict):
            normalized.append(
                serialize_value(item)
            )

        elif isinstance(item, str):

            parsed = parse_legacy_evidence(item)

            normalized.append(parsed)

        else:
            normalized.append(
                serialize_value(item)
            )

    return normalized


def initialize_database():

    connection = get_connection()

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            incident_type TEXT NOT NULL,
            source_ip TEXT,
            risk TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            status TEXT NOT NULL,
            alert_count INTEGER NOT NULL,
            start_time TEXT,
            end_time TEXT,
            mitre_techniques TEXT,
            evidence TEXT,
            ai_investigation TEXT,
            response_playbook TEXT
        )
        """
    )

    existing_columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(incidents)"
        ).fetchall()
    }

    new_columns = {
        "mitre_techniques": "TEXT",
        "evidence": "TEXT",
        "ai_investigation": "TEXT",
        "response_playbook": "TEXT",
    }

    for column, column_type in new_columns.items():

        if column not in existing_columns:

            connection.execute(
                f"ALTER TABLE incidents ADD COLUMN {column} {column_type}"
            )

    connection.commit()
    connection.close()


def save_incident(incident):

    connection = get_connection()

    evidence = normalize_evidence(
        incident.get("evidence", [])
    )

    mitre_techniques = serialize_value(
        incident.get("mitre_techniques", [])
    )

    ai_investigation = serialize_value(
        incident.get("ai_investigation")
    )

    response_playbook = serialize_value(
        incident.get("response_playbook")
    )

    connection.execute(
        """
        INSERT OR REPLACE INTO incidents (
            incident_id,
            incident_type,
            source_ip,
            risk,
            risk_score,
            status,
            alert_count,
            start_time,
            end_time,
            mitre_techniques,
            evidence,
            ai_investigation,
            response_playbook
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            incident["incident_id"],
            incident["type"],
            incident["source_ip"],
            incident["risk"],
            incident["risk_score"],
            incident["status"],
            incident["alert_count"],

            incident["start_time"].isoformat()
            if incident["start_time"]
            else None,

            incident["end_time"].isoformat()
            if incident["end_time"]
            else None,

            json.dumps(mitre_techniques),
            json.dumps(evidence),
            json.dumps(ai_investigation),
            json.dumps(response_playbook),
        ),
    )

    connection.commit()
    connection.close()


def migrate_legacy_evidence():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT incident_id, evidence
        FROM incidents
        """
    ).fetchall()

    migrated_count = 0

    for row in rows:

        raw_evidence = json.loads(
            row["evidence"] or "[]"
        )

        normalized_evidence = normalize_evidence(
            raw_evidence
        )

        if normalized_evidence != raw_evidence:

            connection.execute(
                """
                UPDATE incidents
                SET evidence = ?
                WHERE incident_id = ?
                """,
                (
                    json.dumps(normalized_evidence),
                    row["incident_id"],
                ),
            )

            migrated_count += 1

    connection.commit()
    connection.close()

    return migrated_count


def get_incidents():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT *
        FROM incidents
        ORDER BY start_time DESC
        """
    ).fetchall()

    connection.close()

    incidents = []

    for row in rows:

        incident = dict(row)

        incident["mitre_techniques"] = json.loads(
            incident["mitre_techniques"] or "[]"
        )

        incident["evidence"] = normalize_evidence(
            json.loads(
                incident["evidence"] or "[]"
            )
        )

        incident["ai_investigation"] = json.loads(
            incident["ai_investigation"] or "null"
        )

        incident["response_playbook"] = json.loads(
            incident["response_playbook"] or "null"
        )

        incidents.append(incident)

    return incidents


initialize_database()
migrate_legacy_evidence()