from datetime import datetime

from analyzer.soar.models import SOARAction, SOARExecution
from analyzer.soar.store import SOARExecutionStore


def build_execution():
    now = datetime.now()

    return SOARExecution(
        execution_id="SOAR-TEST1234",
        case_id="CASE-TEST123",
        playbook_id="PB-CREDENTIAL-COMPROMISE",
        playbook_name="Credential Compromise Response",
        status="COMPLETED",
        started_at=now,
        completed_at=now,
        actions=[
            SOARAction(
                action_id="ACTION-TEST123",
                action_type="RESET_CREDENTIALS",
                description="Reset potentially compromised credentials.",
                target="192.168.1.80",
                status="COMPLETED",
                result="Credential reset action simulated.",
                executed_at=now,
            )
        ],
    )


def test_store_saves_and_retrieves_execution(tmp_path):
    store = SOARExecutionStore(
        database_path=tmp_path / "store.db"
    )

    execution = build_execution()
    store.save(execution)

    retrieved = store.get(execution.execution_id)

    assert retrieved is not None
    assert retrieved.execution_id == execution.execution_id
    assert retrieved.case_id == "CASE-TEST123"
    assert retrieved.playbook_id == "PB-CREDENTIAL-COMPROMISE"
    assert retrieved.status == "COMPLETED"
    assert len(retrieved.actions) == 1
    assert retrieved.actions[0].action_type == "RESET_CREDENTIALS"
    assert retrieved.actions[0].target == "192.168.1.80"


def test_store_lists_executions(tmp_path):
    store = SOARExecutionStore(
        database_path=tmp_path / "store.db"
    )

    execution = build_execution()
    store.save(execution)

    executions = store.list_all()

    assert len(executions) == 1
    assert executions[0].execution_id == execution.execution_id


def test_store_returns_none_for_unknown_execution(tmp_path):
    store = SOARExecutionStore(
        database_path=tmp_path / "store.db"
    )

    result = store.get("SOAR-NOTFOUND")

    assert result is None