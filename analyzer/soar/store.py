from datetime import datetime
from pathlib import Path
import json
import sqlite3

from analyzer.database import DATABASE_PATH
from analyzer.soar.models import SOARAction, SOARExecution


class SOARExecutionStore:
    """SQLite persistence layer for SOAR executions and actions."""

    def __init__(self, database_path: str | Path = DATABASE_PATH):
        self.database_path = Path(database_path)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self):
        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS soar_executions (
                    execution_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    playbook_id TEXT NOT NULL,
                    playbook_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    error TEXT,
                    actions TEXT NOT NULL DEFAULT '[]'
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS soar_actions (
                    action_id TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    target TEXT,
                    status TEXT NOT NULL,
                    result TEXT,
                    executed_at TEXT,
                    action_order INTEGER NOT NULL,
                    FOREIGN KEY (execution_id)
                        REFERENCES soar_executions(execution_id)
                        ON DELETE CASCADE
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_soar_actions_execution
                ON soar_actions(execution_id)
                """
            )

            self._migrate_existing_schema(connection)

            connection.commit()

    @staticmethod
    def _migrate_existing_schema(connection):
        """Maintain compatibility with older SOAR database schemas."""

        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(soar_executions)"
            ).fetchall()
        }

        if "actions" not in columns:
            connection.execute(
                """
                ALTER TABLE soar_executions
                ADD COLUMN actions TEXT NOT NULL DEFAULT '[]'
                """
            )

    @staticmethod
    def _serialize_datetime(
        value: datetime | None,
    ) -> str | None:
        if value is None:
            return None

        return value.isoformat()

    @staticmethod
    def _deserialize_datetime(
        value: str | None,
    ) -> datetime | None:
        if value is None:
            return None

        return datetime.fromisoformat(value)

    @staticmethod
    def _serialize_actions(
        actions: list[SOARAction],
    ) -> str:
        return json.dumps(
            [
                {
                    "action_id": action.action_id,
                    "action_type": action.action_type,
                    "description": action.description,
                    "target": action.target,
                    "status": action.status,
                    "result": action.result,
                    "executed_at": (
                        action.executed_at.isoformat()
                        if action.executed_at
                        else None
                    ),
                }
                for action in actions
            ]
        )

    def save_execution(
        self,
        execution: SOARExecution,
    ) -> None:
        actions_json = self._serialize_actions(
            execution.actions
        )

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO soar_executions (
                    execution_id,
                    case_id,
                    playbook_id,
                    playbook_name,
                    status,
                    started_at,
                    completed_at,
                    error,
                    actions
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    execution.execution_id,
                    execution.case_id,
                    execution.playbook_id,
                    execution.playbook_name,
                    execution.status,
                    self._serialize_datetime(
                        execution.started_at
                    ),
                    self._serialize_datetime(
                        execution.completed_at
                    ),
                    execution.error,
                    actions_json,
                ),
            )

            connection.execute(
                """
                DELETE FROM soar_actions
                WHERE execution_id = ?
                """,
                (execution.execution_id,),
            )

            for action_order, action in enumerate(
                execution.actions
            ):
                connection.execute(
                    """
                    INSERT INTO soar_actions (
                        action_id,
                        execution_id,
                        action_type,
                        description,
                        target,
                        status,
                        result,
                        executed_at,
                        action_order
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        action.action_id,
                        execution.execution_id,
                        action.action_type,
                        action.description,
                        action.target,
                        action.status,
                        action.result,
                        self._serialize_datetime(
                            action.executed_at
                        ),
                        action_order,
                    ),
                )

            connection.commit()

    def get_execution(
        self,
        execution_id: str,
    ) -> SOARExecution | None:

        with self._connect() as connection:
            execution_row = connection.execute(
                """
                SELECT *
                FROM soar_executions
                WHERE execution_id = ?
                """,
                (execution_id,),
            ).fetchone()

            if execution_row is None:
                return None

            action_rows = connection.execute(
                """
                SELECT *
                FROM soar_actions
                WHERE execution_id = ?
                ORDER BY action_order ASC
                """,
                (execution_id,),
            ).fetchall()

        actions = [
            SOARAction(
                action_id=row["action_id"],
                action_type=row["action_type"],
                description=row["description"],
                target=row["target"],
                status=row["status"],
                result=row["result"],
                executed_at=self._deserialize_datetime(
                    row["executed_at"]
                ),
            )
            for row in action_rows
        ]

        return SOARExecution(
            execution_id=execution_row["execution_id"],
            case_id=execution_row["case_id"],
            playbook_id=execution_row["playbook_id"],
            playbook_name=execution_row["playbook_name"],
            status=execution_row["status"],
            started_at=self._deserialize_datetime(
                execution_row["started_at"]
            ),
            completed_at=self._deserialize_datetime(
                execution_row["completed_at"]
            ),
            actions=actions,
            error=execution_row["error"],
        )

    def list_executions(self) -> list[SOARExecution]:
        with self._connect() as connection:
            execution_rows = connection.execute(
                """
                SELECT execution_id
                FROM soar_executions
                ORDER BY started_at ASC
                """
            ).fetchall()

        executions = []

        for row in execution_rows:
            execution = self.get_execution(
                row["execution_id"]
            )

            if execution is not None:
                executions.append(execution)

        return executions

    def delete_execution(
        self,
        execution_id: str,
    ) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM soar_executions
                WHERE execution_id = ?
                """,
                (execution_id,),
            )

            connection.commit()

            return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Backward-compatible public API
    # ------------------------------------------------------------------

    def save(self, execution: SOARExecution) -> None:
        """Backward-compatible alias for save_execution()."""
        self.save_execution(execution)

    def get(
        self,
        execution_id: str,
    ) -> SOARExecution | None:
        """Backward-compatible alias for get_execution()."""
        return self.get_execution(execution_id)

    def list(self) -> list[SOARExecution]:
        """Backward-compatible alias for list_executions()."""
        return self.list_executions()

    def list_all(self) -> "list[SOARExecution]":
        """Backward-compatible alias for list_executions()."""
        return self.list_executions()