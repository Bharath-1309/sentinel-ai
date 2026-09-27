from analyzer.soar.models import SOARPlaybook


SOAR_PLAYBOOKS = [
    SOARPlaybook(
        playbook_id="PB-CREDENTIAL-COMPROMISE",
        name="Credential Compromise Response",
        description=(
            "Response workflow for incidents involving credential attacks "
            "or suspected credential compromise."
        ),
        incident_types=[
            "Credential Theft Activity",
            "Windows Credential Attack",
            "Windows Authentication Attack",
            "Potential Account Compromise",
            "SSH Brute Force Incident",
        ],
        minimum_severity="MEDIUM",
        actions=[
            "INVESTIGATE_SOURCE",
            "REVIEW_AUTH_LOGS",
            "RESET_CREDENTIALS",
            "COLLECT_ENDPOINT_EVIDENCE",
            "PRESERVE_SECURITY_LOGS",
        ],
    ),
    SOARPlaybook(
        playbook_id="PB-RECONNAISSANCE",
        name="Reconnaissance Response",
        description=(
            "Response workflow for network reconnaissance and scanning activity."
        ),
        incident_types=[
            "Network Reconnaissance",
        ],
        minimum_severity="MEDIUM",
        actions=[
            "INVESTIGATE_SOURCE",
            "REVIEW_NETWORK_ACTIVITY",
            "CHECK_EXPLOITATION_ATTEMPTS",
            "PRESERVE_SECURITY_LOGS",
        ],
    ),
    SOARPlaybook(
        playbook_id="PB-GENERIC-SECURITY",
        name="Generic Security Incident Response",
        description=(
            "Baseline response workflow for security incidents without "
            "a specialized playbook."
        ),
        incident_types=[],
        minimum_severity="LOW",
        actions=[
            "INVESTIGATE_SOURCE",
            "REVIEW_RELATED_LOGS",
            "IDENTIFY_AFFECTED_SYSTEMS",
            "PRESERVE_SECURITY_LOGS",
            "MONITOR_ACTIVITY",
        ],
    ),
]


def get_playbook(playbook_id: str) -> SOARPlaybook | None:
    for playbook in SOAR_PLAYBOOKS:
        if playbook.playbook_id == playbook_id:
            return playbook

    return None


def list_playbooks() -> list[SOARPlaybook]:
    return list(SOAR_PLAYBOOKS)


def find_playbook(
    incident_type: str,
    severity: str,
) -> SOARPlaybook:
    normalized_type = incident_type.strip().lower()
    normalized_severity = severity.strip().upper()

    severity_order = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    current_level = severity_order.get(normalized_severity, 1)

    # Prefer a specialized playbook.
    for playbook in SOAR_PLAYBOOKS:
        if not playbook.incident_types:
            continue

        if normalized_type in {
            item.lower() for item in playbook.incident_types
        }:
            required_level = severity_order.get(
                playbook.minimum_severity,
                1,
            )

            if current_level >= required_level:
                return playbook

    # Always fall back to the generic security playbook.
    for playbook in SOAR_PLAYBOOKS:
        if not playbook.incident_types:
            return playbook

    raise RuntimeError("No SOAR playbook is configured")