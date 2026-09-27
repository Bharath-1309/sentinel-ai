from datetime import datetime
from uuid import uuid4

from analyzer.case_management.models import Case
from analyzer.soar.models import SOARAction, SOARExecution
from analyzer.soar.playbooks import find_playbook
from analyzer.soar.store import SOARExecutionStore


ACTION_DEFINITIONS = {
    "INVESTIGATE_SOURCE": {
        "description": "Investigate the source of the detected security activity.",
        "result": "Source investigation queued for SOC analysis.",
    },
    "REVIEW_AUTH_LOGS": {
        "description": "Review authentication logs associated with the incident.",
        "result": "Authentication log review queued.",
    },
    "RESET_CREDENTIALS": {
        "description": "Reset potentially compromised credentials.",
        "result": "Credential reset action simulated.",
    },
    "COLLECT_ENDPOINT_EVIDENCE": {
        "description": "Collect forensic evidence from the affected endpoint.",
        "result": "Endpoint evidence collection simulated.",
    },
    "PRESERVE_SECURITY_LOGS": {
        "description": "Preserve relevant security logs for investigation.",
        "result": "Security log preservation simulated.",
    },
    "REVIEW_NETWORK_ACTIVITY": {
        "description": "Review network activity associated with the source.",
        "result": "Network activity review queued.",
    },
    "CHECK_EXPLOITATION_ATTEMPTS": {
        "description": "Check whether reconnaissance was followed by exploitation.",
        "result": "Exploitation check queued.",
    },
    "REVIEW_RELATED_LOGS": {
        "description": "Review security logs related to the incident.",
        "result": "Related log review queued.",
    },
    "IDENTIFY_AFFECTED_SYSTEMS": {
        "description": "Identify systems potentially affected by the incident.",
        "result": "Affected-system identification queued.",
    },
    "MONITOR_ACTIVITY": {
        "description": "Continue monitoring the source for suspicious activity.",
        "result": "Source monitoring action simulated.",
    },
}


class SOAREngine:
    """
    Safe SOAR execution engine.

    Actions are intentionally simulated. The engine creates an auditable
    execution plan without directly changing endpoints, credentials,
    firewalls, or other external systems.

    SOAR executions are persisted in SQLite so they survive
    application/API restarts.
    """

    def __init__(self, store: SOARExecutionStore | None = None):
        self.store = store or SOARExecutionStore()

    @staticmethod
    def _generate_execution_id() -> str:
        return f"SOAR-{uuid4().hex[:8].upper()}"

    @staticmethod
    def _generate_action_id() -> str:
        return f"ACTION-{uuid4().hex[:8].upper()}"

    @staticmethod
    def _get_target(case: Case) -> str | None:
        for evidence in case.evidence:
            if evidence.evidence_type.upper() == "SOURCE_IP":
                return evidence.value

        if case.iocs:
            return case.iocs[0]

        return None

    @staticmethod
    def _build_action(
        action_type: str,
        target: str | None,
    ) -> SOARAction:
        definition = ACTION_DEFINITIONS.get(action_type)

        if definition is None:
            raise ValueError(
                f"Unsupported SOAR action: {action_type}"
            )

        return SOARAction(
            action_id=SOAREngine._generate_action_id(),
            action_type=action_type,
            description=definition["description"],
            target=target,
        )

    def execute_playbook(self, case: Case) -> SOARExecution:
        if case is None:
            raise ValueError("Case is required")

        playbook = find_playbook(
            incident_type=case.title,
            severity=case.severity,
        )

        started_at = datetime.now()

        execution = SOARExecution(
            execution_id=self._generate_execution_id(),
            case_id=case.case_id,
            playbook_id=playbook.playbook_id,
            playbook_name=playbook.name,
            status="RUNNING",
            started_at=started_at,
        )

        target = self._get_target(case)

        try:
            for action_type in playbook.actions:
                action = self._build_action(
                    action_type=action_type,
                    target=target,
                )

                action.status = "RUNNING"
                action.executed_at = datetime.now()

                definition = ACTION_DEFINITIONS[action_type]

                # Safe simulation — no real external action is performed.
                action.result = definition["result"]
                action.status = "COMPLETED"

                execution.actions.append(action)

            execution.status = "COMPLETED"
            execution.completed_at = datetime.now()

        except Exception as error:
            execution.status = "FAILED"
            execution.error = str(error)
            execution.completed_at = datetime.now()

        self.store.save_execution(execution)

        return execution

    def get_execution(
        self,
        execution_id: str,
    ) -> SOARExecution | None:
        return self.store.get_execution(execution_id)

    def list_executions(self) -> list[SOARExecution]:
        return self.store.list_executions()