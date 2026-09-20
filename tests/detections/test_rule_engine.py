from datetime import datetime, timedelta

from analyzer.detections.models import DetectionRule
from analyzer.detections.rule_engine import DetectionRuleEngine


def test_rule_detects_repeated_authentication_failures():

    rule = DetectionRule(
        rule_id="DET-SSH-001",
        name="SSH Brute Force",
        description="Repeated SSH authentication failures",
        event_type="authentication_failure",
        threshold=3,
        window_minutes=5,
        severity="MEDIUM",
        mitre_technique="T1110",
        mitre_tactic="Credential Access",
    )

    start = datetime(2026, 9, 18, 10, 0, 0)

    events = [
        {
            "timestamp": start,
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.50",
            "username": "admin",
        },
        {
            "timestamp": start + timedelta(minutes=1),
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.50",
            "username": "admin",
        },
        {
            "timestamp": start + timedelta(minutes=2),
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.50",
            "username": "admin",
        },
    ]

    engine = DetectionRuleEngine()

    alerts = engine.evaluate(rule, events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "DET-SSH-001"
    assert alerts[0]["source_ip"] == "192.168.1.50"
    assert alerts[0]["event_count"] == 3


def test_rule_does_not_alert_below_threshold():

    rule = DetectionRule(
        rule_id="DET-SSH-001",
        name="SSH Brute Force",
        description="Repeated SSH authentication failures",
        event_type="authentication_failure",
        threshold=3,
        window_minutes=5,
        severity="MEDIUM",
        mitre_technique="T1110",
        mitre_tactic="Credential Access",
    )

    start = datetime(2026, 9, 18, 10, 0, 0)

    events = [
        {
            "timestamp": start,
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.50",
            "username": "admin",
        },
        {
            "timestamp": start + timedelta(minutes=1),
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.50",
            "username": "admin",
        },
    ]

    engine = DetectionRuleEngine()

    alerts = engine.evaluate(rule, events)

    assert alerts == []


def test_disabled_rule_does_not_detect():

    rule = DetectionRule(
        rule_id="DET-SSH-001",
        name="SSH Brute Force",
        description="Repeated SSH authentication failures",
        event_type="authentication_failure",
        threshold=1,
        window_minutes=5,
        severity="MEDIUM",
        mitre_technique="T1110",
        mitre_tactic="Credential Access",
        enabled=False,
    )

    events = [
        {
            "timestamp": datetime(2026, 9, 18, 10, 0, 0),
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.50",
            "username": "admin",
        }
    ]

    engine = DetectionRuleEngine()

    alerts = engine.evaluate(rule, events)

    assert alerts == []

def test_password_spray_requires_multiple_usernames():
    from datetime import datetime, timedelta

    from analyzer.detections.models import DetectionRule
    from analyzer.detections.rule_engine import DetectionRuleEngine

    rule = DetectionRule(
        rule_id="DET-SSH-002",
        name="SSH Password Spraying",
        description="Test password spraying",
        event_type="authentication_failure",
        threshold=3,
        window_minutes=5,
        severity="HIGH",
        mitre_technique="T1110.003",
        mitre_tactic="Credential Access",
        enabled=True,
    )

    base_time = datetime(2026, 9, 20, 10, 0, 0)

    events = [
        {
            "timestamp": base_time + timedelta(seconds=index),
            "event_type": "authentication_failure",
            "username": "admin",
            "source_ip": "192.168.1.50",
        }
        for index in range(3)
    ]

    alerts = DetectionRuleEngine().evaluate(rule, events)

    assert alerts == []    