import pytest
from datetime import datetime

from analyzer.case_management.models import Case, CaseEvidence
from analyzer.soar.engine import SOAREngine
from analyzer.soar.store import SOARExecutionStore


@pytest.fixture
def engine(tmp_path):
    """
    Use an isolated temporary database for each test.

    Production SOAR uses sentinelai.db, but tests must not depend
    on executions created by previous test runs.
    """
    database_path = tmp_path / "soar_test.db"

    return SOAREngine(
        store=SOARExecutionStore(database_path)
    )


def build_case():
    now = datetime.now()

    return Case(
        case_id="CASE-TEST123",
        incident_id="INC-TEST123",
        title="Credential Theft Activity",
        description="Test credential theft incident",
        severity="CRITICAL",
        status="OPEN",
        assigned_to=None,
        created_at=now,
        updated_at=now,
        notes=[],
        evidence=[
            CaseEvidence(
                evidence_id=1,
                evidence_type="SOURCE_IP",
                value="192.168.1.80",
                source="INCIDENT",
                created_at=now,
            )
        ],
        iocs=[],
        mitre_techniques=[],
        ai_investigation=None,
    )


def test_soar_executes_credential_playbook(engine):
    case = build_case()

    execution = engine.execute_playbook(case)

    assert execution.status == "COMPLETED"
    assert execution.case_id == "CASE-TEST123"
    assert execution.playbook_id == "PB-CREDENTIAL-COMPROMISE"
    assert execution.playbook_name == "Credential Compromise Response"
    assert len(execution.actions) == 5

    for action in execution.actions:
        assert action.status == "COMPLETED"
        assert action.target == "192.168.1.80"
        assert action.result is not None


def test_soar_does_not_execute_real_external_actions(engine):
    case = build_case()

    execution = engine.execute_playbook(case)

    results = [
        action.result
        for action in execution.actions
    ]

    assert "Credential reset action simulated." in results
    assert "Endpoint evidence collection simulated." in results


def test_soar_execution_is_stored(engine):
    case = build_case()

    execution = engine.execute_playbook(case)

    stored = engine.get_execution(
        execution.execution_id
    )

    assert stored is not None
    assert stored.execution_id == execution.execution_id


def test_soar_lists_executions(engine):
    case = build_case()

    first = engine.execute_playbook(case)
    second = engine.execute_playbook(case)

    executions = engine.list_executions()

    assert len(executions) == 2
    assert executions[0].execution_id == first.execution_id
    assert executions[1].execution_id == second.execution_id


def test_soar_execution_persists_across_engine_instances(tmp_path):
    database_path = tmp_path / "soar_persistence.db"

    first_engine = SOAREngine(
        store=SOARExecutionStore(database_path)
    )

    case = build_case()

    execution = first_engine.execute_playbook(case)

    second_engine = SOAREngine(
        store=SOARExecutionStore(database_path)
    )

    restored = second_engine.get_execution(
        execution.execution_id
    )

    assert restored is not None
    assert restored.execution_id == execution.execution_id
    assert restored.case_id == "CASE-TEST123"
    assert restored.playbook_id == "PB-CREDENTIAL-COMPROMISE"
    assert restored.status == "COMPLETED"
    assert len(restored.actions) == 5


def test_soar_persistence_restores_action_details(tmp_path):
    database_path = tmp_path / "soar_actions.db"

    first_engine = SOAREngine(
        store=SOARExecutionStore(database_path)
    )

    execution = first_engine.execute_playbook(
        build_case()
    )

    second_engine = SOAREngine(
        store=SOARExecutionStore(database_path)
    )

    restored = second_engine.get_execution(
        execution.execution_id
    )

    assert restored is not None

    original_actions = execution.actions
    restored_actions = restored.actions

    assert len(restored_actions) == len(original_actions)

    for original, restored_action in zip(
        original_actions,
        restored_actions,
    ):
        assert restored_action.action_id == original.action_id
        assert (
            restored_action.action_type
            == original.action_type
        )
        assert (
            restored_action.description
            == original.description
        )
        assert restored_action.target == original.target
        assert restored_action.status == original.status
        assert restored_action.result == original.result
        assert (
            restored_action.executed_at
            == original.executed_at
        )