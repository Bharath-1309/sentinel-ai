from analyzer.correlation.engine import AdvancedCorrelationEngine
from datetime import datetime, timedelta


def test_reconnaissance_followed_by_brute_force():
    alerts = [
        {
            "type": "Network Service Scanning",
            "ip": "192.168.1.50",
            "risk": "HIGH",
        },
        {
            "type": "SSH Brute Force",
            "ip": "192.168.1.50",
            "risk": "MEDIUM",
        },
    ]

    results = AdvancedCorrelationEngine().correlate(alerts)

    assert len(results) == 1
    assert results[0].correlation_id == "CORR-001"
    assert results[0].severity == "HIGH"
    assert results[0].source_ip == "192.168.1.50"


def test_no_correlation_for_unrelated_alerts():
    alerts = [
        {
            "type": "Network Service Scanning",
            "ip": "192.168.1.50",
            "risk": "HIGH",
        },
    ]

    results = AdvancedCorrelationEngine().correlate(alerts)

    assert results == []

def test_credential_attack_followed_by_successful_login():
    alerts = [
        {
            "type": "SSH Brute Force",
            "ip": "10.10.10.25",
            "risk": "MEDIUM",
        },
        {
            "type": "Successful Login",
            "ip": "10.10.10.25",
            "risk": "HIGH",
        },
    ]

    results = AdvancedCorrelationEngine().correlate(alerts)

    assert len(results) == 1
    assert results[0].correlation_id == "CORR-002"
    assert results[0].severity == "CRITICAL"


def test_credential_attack_and_credential_dumping():
    alerts = [
        {
            "type": "SSH Brute Force",
            "ip": "10.10.10.30",
            "risk": "MEDIUM",
        },
        {
            "type": "Credential Dumping",
            "ip": "10.10.10.30",
            "risk": "CRITICAL",
        },
    ]

    results = AdvancedCorrelationEngine().correlate(alerts)

    assert len(results) == 1
    assert results[0].correlation_id == "CORR-003"
    assert results[0].severity == "CRITICAL"

def test_correlation_does_not_mix_source_ips():
    alerts = [
        {
            "type": "Network Service Scanning",
            "ip": "192.168.1.50",
            "risk": "HIGH",
        },
        {
            "type": "SSH Brute Force",
            "ip": "10.10.10.25",
            "risk": "MEDIUM",
        },
    ]

    results = AdvancedCorrelationEngine().correlate(alerts)

    assert results == []  

def test_reconnaissance_after_brute_force_does_not_correlate():
    alerts = [
        {
            "type": "SSH Brute Force",
            "ip": "192.168.1.50",
            "risk": "MEDIUM",
        },
        {
            "type": "Network Service Scanning",
            "ip": "192.168.1.50",
            "risk": "HIGH",
        },
    ]

    results = AdvancedCorrelationEngine().correlate(alerts)

    assert results == []


def test_successful_login_before_brute_force_does_not_correlate():
    alerts = [
        {
            "type": "Successful Login",
            "ip": "10.10.10.25",
            "risk": "HIGH",
        },
        {
            "type": "SSH Brute Force",
            "ip": "10.10.10.25",
            "risk": "MEDIUM",
        },
    ]

    results = AdvancedCorrelationEngine().correlate(alerts)

    assert results == []      



def test_correlation_outside_time_window_does_not_trigger():
    start_time = datetime(2026, 9, 15, 10, 0, 0)
    later_time = start_time + timedelta(minutes=16)

    alerts = [
        {
            "type": "Network Service Scanning",
            "ip": "192.168.1.50",
            "risk": "HIGH",
            "timestamp": start_time,
        },
        {
            "type": "SSH Brute Force",
            "ip": "192.168.1.50",
            "risk": "MEDIUM",
            "timestamp": later_time,
        },
    ]

    results = AdvancedCorrelationEngine().correlate(alerts)

    assert results == []    

def test_correlation_inside_time_window_triggers():
    start_time = datetime(2026, 9, 15, 10, 0, 0)
    later_time = start_time + timedelta(minutes=10)

    alerts = [
        {
            "type": "Network Service Scanning",
            "ip": "192.168.1.50",
            "risk": "HIGH",
            "timestamp": start_time,
        },
        {
            "type": "SSH Brute Force",
            "ip": "192.168.1.50",
            "risk": "MEDIUM",
            "timestamp": later_time,
        },
    ]

    results = AdvancedCorrelationEngine().correlate(alerts)

    assert len(results) == 1
    assert results[0].correlation_id == "CORR-001"
    assert results[0].severity == "HIGH"    

def test_duplicate_correlation_is_returned_only_once():
    alerts = [
        {
            "type": "Network Service Scanning",
            "ip": "192.168.1.50",
            "risk": "HIGH",
        },
        {
            "type": "SSH Brute Force",
            "ip": "192.168.1.50",
            "risk": "MEDIUM",
        },
        {
            "type": "Network Service Scanning",
            "ip": "192.168.1.50",
            "risk": "HIGH",
        },
        {
            "type": "SSH Brute Force",
            "ip": "192.168.1.50",
            "risk": "MEDIUM",
        },
    ]

    results = AdvancedCorrelationEngine().correlate(alerts)

    assert len(results) == 1
    assert results[0].correlation_id == "CORR-001"    

def test_unrelated_alert_outside_window_does_not_break_correlation():
    start_time = datetime(2026, 9, 15, 10, 0, 0)

    alerts = [
        {
            "type": "Network Service Scanning",
            "ip": "192.168.1.50",
            "risk": "HIGH",
            "timestamp": start_time,
        },
        {
            "type": "SSH Brute Force",
            "ip": "192.168.1.50",
            "risk": "MEDIUM",
            "timestamp": start_time + timedelta(minutes=10),
        },
        {
            "type": "PowerShell",
            "ip": "192.168.1.50",
            "risk": "HIGH",
            "timestamp": start_time + timedelta(minutes=30),
        },
    ]

    results = AdvancedCorrelationEngine().correlate(alerts)

    assert len(results) == 1
    assert results[0].correlation_id == "CORR-001"    