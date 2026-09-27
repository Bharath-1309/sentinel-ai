import json
import sqlite3
import uuid
from datetime import datetime

from analyzer.database import get_connection
from analyzer.case_management.models import (
    CASE_SEVERITIES,
    CASE_STATUSES,
    Case,
    CaseEvidence,
    CaseNote,
)


class CaseManager:

    def __init__(self):
        self._initialize_tables()

    # ============================================================
    # DATABASE
    # ============================================================

    def _initialize_tables(self):
        connection = get_connection()

        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assigned_to TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    ai_investigation TEXT
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS case_notes (
                    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    author TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS case_evidence (
                    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )

            columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(cases)"
                ).fetchall()
            }

            if "ai_investigation" not in columns:
                connection.execute(
                    """
                    ALTER TABLE cases
                    ADD COLUMN ai_investigation TEXT
                    """
                )

            connection.commit()

        finally:
            connection.close()

    # ============================================================
    # HELPERS
    # ============================================================

    @staticmethod
    def _generate_case_id():
        return f"CASE-{uuid.uuid4().hex[:8].upper()}"

    @staticmethod
    def _validate_severity(severity):
        severity = severity.upper()

        if severity not in CASE_SEVERITIES:
            raise ValueError(
                f"Invalid case severity: {severity}"
            )

        return severity

    @staticmethod
    def _validate_status(status):
        status = status.upper()

        if status not in CASE_STATUSES:
            raise ValueError(
                f"Invalid case status: {status}"
            )

        return status

    @staticmethod
    def _parse_datetime(value):
        if isinstance(value, datetime):
            return value

        return datetime.fromisoformat(value)

    # ============================================================
    # CREATE
    # ============================================================

    def create_case(
        self,
        incident_id,
        title,
        description="",
        severity="MEDIUM",
        assigned_to=None,
    ):
        if not incident_id or not incident_id.strip():
            raise ValueError("incident_id is required")

        if not title or not title.strip():
            raise ValueError("title is required")

        severity = self._validate_severity(severity)

        now = datetime.now()
        case_id = self._generate_case_id()

        connection = get_connection()

        try:
            connection.execute(
                """
                INSERT INTO cases (
                    case_id,
                    incident_id,
                    title,
                    description,
                    severity,
                    status,
                    assigned_to,
                    created_at,
                    updated_at,
                    ai_investigation
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    incident_id,
                    title.strip(),
                    description or "",
                    severity,
                    "OPEN",
                    assigned_to,
                    now.isoformat(),
                    now.isoformat(),
                    None,
                ),
            )

            connection.commit()

        finally:
            connection.close()

        return self.get_case(case_id)

    # ============================================================
    # CREATE CASE FROM INCIDENT
    # ============================================================

    def create_case_from_incident(self, incident):
        """
        Convert an existing SentinelAI incident into a SOC case.

        The incident remains the source record.
        The case becomes the investigation workspace.
        """

        if not incident:
            raise ValueError("incident is required")

        incident_id = incident.get("incident_id")

        if not incident_id:
            raise ValueError("incident_id is required")

        incident_type = (
            incident.get("type")
            or incident.get("incident_type")
            or "Security Incident"
        )

        risk = (
            incident.get("risk")
            or "MEDIUM"
        )

        risk = self._validate_severity(risk)

        source_ip = incident.get("source_ip")

        description_parts = [
            f"Incident ID: {incident_id}",
            f"Incident Type: {incident_type}",
        ]

        if source_ip:
            description_parts.append(
                f"Source IP: {source_ip}"
            )

        if incident.get("risk_score") is not None:
            description_parts.append(
                f"Risk Score: {incident['risk_score']}"
            )

        if incident.get("alert_count") is not None:
            description_parts.append(
                f"Alert Count: {incident['alert_count']}"
            )

        description = "\n".join(description_parts)

        case = self.create_case(
            incident_id=incident_id,
            title=incident_type,
            description=description,
            severity=risk,
        )

        # Preserve important incident evidence inside the case.
        if source_ip:
            self.add_evidence(
                case.case_id,
                evidence_type="SOURCE_IP",
                value=str(source_ip),
                source="INCIDENT",
            )

        for technique in incident.get("mitre_techniques", []):
            if isinstance(technique, dict):
                technique_id = technique.get("technique_id")

                if technique_id:
                    self.add_evidence(
                        case.case_id,
                        evidence_type="MITRE_TECHNIQUE",
                        value=str(technique_id),
                        source="INCIDENT",
                    )

        for evidence in incident.get("evidence", []):
            if not isinstance(evidence, dict):
                continue

            value = (
                evidence.get("message")
                or evidence.get("raw_log")
                or evidence.get("ip")
            )

            if not value:
                continue

            self.add_evidence(
                case.case_id,
                evidence_type="ALERT_EVIDENCE",
                value=str(value),
                source="INCIDENT",
            )

        return self.get_case(case.case_id)

    # ============================================================
    # GET
    # ============================================================

    def get_case(self, case_id):
        connection = get_connection()

        try:
            row = connection.execute(
                """
                SELECT *
                FROM cases
                WHERE case_id = ?
                """,
                (case_id,),
            ).fetchone()

            if row is None:
                return None

            note_rows = connection.execute(
                """
                SELECT *
                FROM case_notes
                WHERE case_id = ?
                ORDER BY created_at ASC, note_id ASC
                """,
                (case_id,),
            ).fetchall()

            evidence_rows = connection.execute(
                """
                SELECT *
                FROM case_evidence
                WHERE case_id = ?
                ORDER BY created_at ASC, evidence_id ASC
                """,
                (case_id,),
            ).fetchall()

            notes = [
                CaseNote(
                    note_id=note["note_id"],
                    author=note["author"],
                    content=note["content"],
                    created_at=self._parse_datetime(
                        note["created_at"]
                    ),
                )
                for note in note_rows
            ]

            evidence = [
                CaseEvidence(
                    evidence_id=item["evidence_id"],
                    evidence_type=item["evidence_type"],
                    value=item["value"],
                    source=item["source"],
                    created_at=self._parse_datetime(
                        item["created_at"]
                    ),
                )
                for item in evidence_rows
            ]

            ai_investigation = None

            if row["ai_investigation"]:
                try:
                    ai_investigation = json.loads(
                        row["ai_investigation"]
                    )
                except (json.JSONDecodeError, TypeError):
                    ai_investigation = None

            return Case(
                case_id=row["case_id"],
                incident_id=row["incident_id"],
                title=row["title"],
                description=row["description"],
                severity=row["severity"],
                status=row["status"],
                assigned_to=row["assigned_to"],
                created_at=self._parse_datetime(
                    row["created_at"]
                ),
                updated_at=self._parse_datetime(
                    row["updated_at"]
                ),
                notes=notes,
                evidence=evidence,
                iocs=[],
                mitre_techniques=[],
                ai_investigation=ai_investigation,
            )

        finally:
            connection.close()

    # ============================================================
    # LIST
    # ============================================================

    def list_cases(
        self,
        status=None,
        severity=None,
    ):
        if status is not None:
            status = self._validate_status(status)

        if severity is not None:
            severity = self._validate_severity(severity)

        query = """
            SELECT case_id
            FROM cases
            WHERE 1 = 1
        """

        parameters = []

        if status is not None:
            query += " AND status = ?"
            parameters.append(status)

        if severity is not None:
            query += " AND severity = ?"
            parameters.append(severity)

        query += " ORDER BY updated_at DESC"

        connection = get_connection()

        try:
            rows = connection.execute(
                query,
                parameters,
            ).fetchall()

            return [
                self.get_case(row["case_id"])
                for row in rows
            ]

        finally:
            connection.close()

    # ============================================================
    # UPDATE
    # ============================================================

    def update_case(
        self,
        case_id,
        title=None,
        description=None,
        severity=None,
        status=None,
        assigned_to=None,
    ):
        case = self.get_case(case_id)

        if case is None:
            return None

        if severity is not None:
            severity = self._validate_severity(severity)

        if status is not None:
            status = self._validate_status(status)

        updates = []
        parameters = []

        if title is not None:
            if not title.strip():
                raise ValueError("title cannot be empty")

            updates.append("title = ?")
            parameters.append(title.strip())

        if description is not None:
            updates.append("description = ?")
            parameters.append(description)

        if severity is not None:
            updates.append("severity = ?")
            parameters.append(severity)

        if status is not None:
            updates.append("status = ?")
            parameters.append(status)

        if assigned_to is not None:
            updates.append("assigned_to = ?")
            parameters.append(assigned_to)

        if not updates:
            return case

        updates.append("updated_at = ?")
        parameters.append(datetime.now().isoformat())

        parameters.append(case_id)

        connection = get_connection()

        try:
            connection.execute(
                f"""
                UPDATE cases
                SET {", ".join(updates)}
                WHERE case_id = ?
                """,
                parameters,
            )

            connection.commit()

        finally:
            connection.close()

        return self.get_case(case_id)

    # ============================================================
    # AI INVESTIGATION
    # ============================================================

    def save_ai_investigation(
        self,
        case_id,
        investigation,
    ):
        if self.get_case(case_id) is None:
            return None

        connection = get_connection()

        try:
            connection.execute(
                """
                UPDATE cases
                SET
                    ai_investigation = ?,
                    updated_at = ?
                WHERE case_id = ?
                """,
                (
                    json.dumps(investigation),
                    datetime.now().isoformat(),
                    case_id,
                ),
            )

            connection.commit()

        finally:
            connection.close()

        return self.get_case(case_id)

    # ============================================================
    # NOTES
    # ============================================================

    def add_note(
        self,
        case_id,
        author,
        content,
    ):
        if self.get_case(case_id) is None:
            raise ValueError("Case not found")

        if not author or not author.strip():
            raise ValueError("author is required")

        if not content or not content.strip():
            raise ValueError("content is required")

        now = datetime.now()

        connection = get_connection()

        try:
            cursor = connection.execute(
                """
                INSERT INTO case_notes (
                    case_id,
                    author,
                    content,
                    created_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    case_id,
                    author.strip(),
                    content.strip(),
                    now.isoformat(),
                ),
            )

            connection.execute(
                """
                UPDATE cases
                SET updated_at = ?
                WHERE case_id = ?
                """,
                (
                    now.isoformat(),
                    case_id,
                ),
            )

            connection.commit()

            note_id = cursor.lastrowid

        finally:
            connection.close()

        return CaseNote(
            note_id=note_id,
            author=author.strip(),
            content=content.strip(),
            created_at=now,
        )

    # ============================================================
    # EVIDENCE
    # ============================================================

    def add_evidence(
        self,
        case_id,
        evidence_type,
        value,
        source=None,
    ):
        if self.get_case(case_id) is None:
            raise ValueError("Case not found")

        if not evidence_type or not evidence_type.strip():
            raise ValueError("evidence_type is required")

        if not value or not value.strip():
            raise ValueError("value is required")

        now = datetime.now()

        connection = get_connection()

        try:
            cursor = connection.execute(
                """
                INSERT INTO case_evidence (
                    case_id,
                    evidence_type,
                    value,
                    source,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    evidence_type.strip(),
                    value.strip(),
                    source,
                    now.isoformat(),
                ),
            )

            connection.execute(
                """
                UPDATE cases
                SET updated_at = ?
                WHERE case_id = ?
                """,
                (
                    now.isoformat(),
                    case_id,
                ),
            )

            connection.commit()

            evidence_id = cursor.lastrowid

        finally:
            connection.close()

        return CaseEvidence(
            evidence_id=evidence_id,
            evidence_type=evidence_type.strip(),
            value=value.strip(),
            source=source,
            created_at=now,
        )

    # ============================================================
    # DELETE
    # ============================================================

    def delete_case(self, case_id):
        if self.get_case(case_id) is None:
            return False

        connection = get_connection()

        try:
            connection.execute(
                """
                DELETE FROM case_notes
                WHERE case_id = ?
                """,
                (case_id,),
            )

            connection.execute(
                """
                DELETE FROM case_evidence
                WHERE case_id = ?
                """,
                (case_id,),
            )

            connection.execute(
                """
                DELETE FROM cases
                WHERE case_id = ?
                """,
                (case_id,),
            )

            connection.commit()

        finally:
            connection.close()

        return True