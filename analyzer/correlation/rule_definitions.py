from .rules import CorrelationRule


CORRELATION_RULES = [
    CorrelationRule(
        correlation_id="CORR-001",
        name="Reconnaissance Followed by Credential Attack",
        description=(
            "Detect network reconnaissance followed by "
            "an authentication attack from the same source."
        ),
        required_alert_types={
            "Network Service Scanning",
            "SSH Brute Force",
        },
        severity="HIGH",
    ),
    CorrelationRule(
        correlation_id="CORR-002",
        name="Credential Attack Followed by Successful Login",
        description=(
            "Detect authentication attacks followed by "
            "a successful login from the same source."
        ),
        required_alert_types={
            "SSH Brute Force",
            "Successful Login",
        },
        severity="CRITICAL",
    ),
    CorrelationRule(
        correlation_id="CORR-003",
        name="Credential Attack and Credential Dumping",
        description=(
            "Detect credential attacks combined with "
            "credential dumping activity."
        ),
        required_alert_types={
            "SSH Brute Force",
            "Credential Dumping",
        },
        severity="CRITICAL",
    ),
]
