from analyzer.case_management.manager import CaseManager


def test_create_case():
    manager = CaseManager()

    case = manager.create_case(
        incident_id="INC-TEST-001",
        title="SSH Brute Force Investigation",
        description="Investigate repeated SSH authentication failures.",
        severity="HIGH",
        assigned_to="analyst1",
    )

    assert case.case_id.startswith("CASE-")
    assert case.incident_id == "INC-TEST-001"
    assert case.title == "SSH Brute Force Investigation"
    assert case.severity == "HIGH"
    assert case.status == "OPEN"
    assert case.assigned_to == "analyst1"


def test_get_case():
    manager = CaseManager()

    created = manager.create_case(
        incident_id="INC-TEST-002",
        title="Credential Attack",
    )

    case = manager.get_case(created.case_id)

    assert case is not None
    assert case.case_id == created.case_id
    assert case.incident_id == "INC-TEST-002"


def test_get_missing_case():
    manager = CaseManager()

    assert manager.get_case("CASE-NOT-FOUND") is None


def test_update_case_status():
    manager = CaseManager()

    case = manager.create_case(
        incident_id="INC-TEST-003",
        title="Network Attack",
    )

    updated = manager.update_case(
        case.case_id,
        status="INVESTIGATING",
    )

    assert updated is not None
    assert updated.status == "INVESTIGATING"


def test_update_case_severity():
    manager = CaseManager()

    case = manager.create_case(
        incident_id="INC-TEST-004",
        title="Malicious Activity",
    )

    updated = manager.update_case(
        case.case_id,
        severity="CRITICAL",
    )

    assert updated is not None
    assert updated.severity == "CRITICAL"


def test_assign_case():
    manager = CaseManager()

    case = manager.create_case(
        incident_id="INC-TEST-005",
        title="Suspicious Login",
    )

    updated = manager.update_case(
        case.case_id,
        assigned_to="soc_analyst",
    )

    assert updated is not None
    assert updated.assigned_to == "soc_analyst"


def test_add_case_note():
    manager = CaseManager()

    case = manager.create_case(
        incident_id="INC-TEST-006",
        title="Account Compromise",
    )

    note = manager.add_note(
        case_id=case.case_id,
        author="analyst1",
        content="Reviewed authentication events.",
    )

    assert note.note_id is not None
    assert note.author == "analyst1"
    assert note.content == "Reviewed authentication events."

    updated = manager.get_case(case.case_id)

    assert updated is not None
    assert len(updated.notes) == 1
    assert updated.notes[0].content == (
        "Reviewed authentication events."
    )


def test_add_case_evidence():
    manager = CaseManager()

    case = manager.create_case(
        incident_id="INC-TEST-007",
        title="Malicious IP Investigation",
    )

    evidence = manager.add_evidence(
        case_id=case.case_id,
        evidence_type="IOC",
        value="192.168.1.50",
        source="AbuseIPDB",
    )

    assert evidence.evidence_id is not None
    assert evidence.evidence_type == "IOC"
    assert evidence.value == "192.168.1.50"
    assert evidence.source == "AbuseIPDB"

    updated = manager.get_case(case.case_id)

    assert updated is not None
    assert len(updated.evidence) == 1
    assert updated.evidence[0].value == "192.168.1.50"


def test_list_cases():
    manager = CaseManager()

    case = manager.create_case(
        incident_id="INC-TEST-008",
        title="High Severity Case",
        severity="HIGH",
    )

    cases = manager.list_cases(
        severity="HIGH",
    )

    assert any(
        item.case_id == case.case_id
        for item in cases
    )


def test_list_cases_by_status():
    manager = CaseManager()

    case = manager.create_case(
        incident_id="INC-TEST-009",
        title="Investigation Case",
    )

    manager.update_case(
        case.case_id,
        status="INVESTIGATING",
    )

    cases = manager.list_cases(
        status="INVESTIGATING",
    )

    assert any(
        item.case_id == case.case_id
        for item in cases
    )


def test_invalid_status():
    manager = CaseManager()

    try:
        manager.create_case(
            incident_id="INC-TEST-010",
            title="Invalid Case",
            severity="INVALID",
        )
        assert False
    except ValueError as exc:
        assert "severity" in str(exc)


def test_invalid_update_status():
    manager = CaseManager()

    case = manager.create_case(
        incident_id="INC-TEST-011",
        title="Test Case",
    )

    try:
        manager.update_case(
            case.case_id,
            status="INVALID",
        )
        assert False
    except ValueError as exc:
        assert "status" in str(exc)


def test_delete_case():
    manager = CaseManager()

    case = manager.create_case(
        incident_id="INC-TEST-012",
        title="Delete Test",
    )

    manager.add_note(
        case.case_id,
        "analyst",
        "Temporary note",
    )

    manager.add_evidence(
        case.case_id,
        "IOC",
        "example.com",
        "test",
    )

    assert manager.delete_case(case.case_id) is True
    assert manager.get_case(case.case_id) is None


def test_delete_missing_case():
    manager = CaseManager()

    assert manager.delete_case(
        "CASE-NOT-FOUND"
    ) is False


def test_case_rejects_empty_title():
    manager = CaseManager()

    try:
        manager.create_case(
            incident_id="INC-TEST-013",
            title="",
        )
        assert False
    except ValueError as exc:
        assert "title" in str(exc)


def test_case_rejects_empty_incident():
    manager = CaseManager()

    try:
        manager.create_case(
            incident_id="",
            title="Test Case",
        )
        assert False
    except ValueError as exc:
        assert "incident_id" in str(exc)