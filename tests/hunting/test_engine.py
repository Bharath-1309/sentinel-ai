from datetime import datetime

from analyzer.hunting.engine import ThreatHuntingEngine
from analyzer.hunting.models import (
    HuntingQuery,
    HuntingQueryGroup,
    HuntingTimeRange,
    HuntingSearch,
)


def test_hunting_query_matches_exact_field():
    events = [
        {
            "event_type": "authentication_failure",
            "username": "admin",
            "source_ip": "192.168.1.50",
        },
        {
            "event_type": "authentication_success",
            "username": "admin",
            "source_ip": "192.168.1.50",
        },
    ]

    query = HuntingQuery(
        field="username",
        operator="equals",
        value="admin",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert len(results) == 2


def test_hunting_query_returns_only_matching_events():
    events = [
        {
            "event_type": "authentication_failure",
            "username": "admin",
            "source_ip": "192.168.1.50",
        },
        {
            "event_type": "authentication_failure",
            "username": "root",
            "source_ip": "10.10.10.25",
        },
    ]

    query = HuntingQuery(
        field="username",
        operator="equals",
        value="root",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert len(results) == 1
    assert results[0]["source_ip"] == "10.10.10.25"

def test_hunting_query_supports_contains():
    events = [
        {
            "event_type": "authentication_failure",
            "message": "SSH authentication failure for admin",
        },
        {
            "event_type": "authentication_success",
            "message": "Successful SSH login",
        },
    ]

    query = HuntingQuery(
        field="message",
        operator="contains",
        value="authentication failure",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert len(results) == 1
    assert results[0]["event_type"] == "authentication_failure"

def test_hunting_query_supports_multiple_conditions_with_and():
    events = [
        {
            "event_type": "authentication_failure",
            "username": "admin",
            "source_ip": "192.168.1.50",
        },
        {
            "event_type": "authentication_success",
            "username": "admin",
            "source_ip": "192.168.1.50",
        },
        {
            "event_type": "authentication_failure",
            "username": "root",
            "source_ip": "10.10.10.25",
        },
    ]

    query = HuntingQueryGroup(
        queries=[
            HuntingQuery(
                field="event_type",
                operator="equals",
                value="authentication_failure",
            ),
            HuntingQuery(
                field="username",
                operator="equals",
                value="admin",
            ),
        ],
        logic="AND",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert len(results) == 1
    assert results[0]["username"] == "admin"
    assert results[0]["event_type"] == "authentication_failure"    

def test_hunting_query_supports_multiple_conditions_with_or():
    events = [
        {
            "event_type": "authentication_failure",
            "username": "admin",
            "source_ip": "192.168.1.50",
        },
        {
            "event_type": "authentication_success",
            "username": "root",
            "source_ip": "10.10.10.25",
        },
        {
            "event_type": "network_connection",
            "username": "guest",
            "source_ip": "10.10.10.30",
        },
    ]

    query = HuntingQueryGroup(
        queries=[
            HuntingQuery(
                field="username",
                operator="equals",
                value="admin",
            ),
            HuntingQuery(
                field="event_type",
                operator="equals",
                value="network_connection",
            ),
        ],
        logic="OR",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert len(results) == 2
    assert results[0]["username"] == "admin"
    assert results[1]["event_type"] == "network_connection"   

def test_hunting_query_supports_not_equals():
    events = [
        {
            "event_type": "authentication_failure",
            "username": "admin",
        },
        {
            "event_type": "authentication_success",
            "username": "admin",
        },
    ]

    query = HuntingQuery(
        field="event_type",
        operator="not_equals",
        value="authentication_success",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert len(results) == 1
    assert results[0]["event_type"] == "authentication_failure" 

def test_hunting_query_supports_greater_than():
    events = [
        {
            "username": "admin",
            "failed_attempts": 5,
        },
        {
            "username": "root",
            "failed_attempts": 2,
        },
    ]

    query = HuntingQuery(
        field="failed_attempts",
        operator="greater_than",
        value="3",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert len(results) == 1
    assert results[0]["username"] == "admin" 

def test_hunting_query_handles_invalid_numeric_value():
    events = [
        {
            "username": "admin",
            "failed_attempts": 5,
        }
    ]

    query = HuntingQuery(
        field="failed_attempts",
        operator="greater_than",
        value="invalid",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert results == []           

def test_hunting_query_supports_time_range():
    events = [
        {
            "event_type": "authentication_failure",
            "timestamp": datetime(2026, 9, 20, 10, 5, 0),
        },
        {
            "event_type": "authentication_failure",
            "timestamp": datetime(2026, 9, 20, 10, 20, 0),
        },
    ]

    query = HuntingTimeRange(
        start=datetime(2026, 9, 20, 10, 0, 0),
        end=datetime(2026, 9, 20, 10, 10, 0),
    )

    results = ThreatHuntingEngine().search(events, query)

    assert len(results) == 1
    assert results[0]["timestamp"] == datetime(
        2026, 9, 20, 10, 5, 0
    )

def test_hunting_search_combines_time_range_and_conditions():
    events = [
        {
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.50",
            "timestamp": datetime(2026, 9, 20, 10, 5, 0),
        },
        {
            "event_type": "authentication_success",
            "source_ip": "192.168.1.50",
            "timestamp": datetime(2026, 9, 20, 10, 10, 0),
        },
        {
            "event_type": "authentication_failure",
            "source_ip": "10.10.10.25",
            "timestamp": datetime(2026, 9, 20, 10, 7, 0),
        },
        {
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.50",
            "timestamp": datetime(2026, 9, 20, 10, 40, 0),
        },
    ]

    query = HuntingSearch(
        conditions=HuntingQueryGroup(
            queries=[
                HuntingQuery(
                    field="event_type",
                    operator="equals",
                    value="authentication_failure",
                ),
                HuntingQuery(
                    field="source_ip",
                    operator="equals",
                    value="192.168.1.50",
                ),
            ],
            logic="AND",
        ),
        time_range=HuntingTimeRange(
            start=datetime(2026, 9, 20, 10, 0, 0),
            end=datetime(2026, 9, 20, 10, 30, 0),
        ),
    )

    results = ThreatHuntingEngine().search(events, query)

    assert len(results) == 1
    assert results[0]["source_ip"] == "192.168.1.50"
    assert results[0]["event_type"] == "authentication_failure"     

def test_hunting_query_rejects_unknown_field():
    from analyzer.hunting.engine import ThreatHuntingEngine
    from analyzer.hunting.models import HuntingQuery

    events = [
        {
            "username": "admin",
            "event_type": "authentication_failure",
        }
    ]

    query = HuntingQuery(
        field="unknown_field",
        operator="equals",
        value="admin",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert results == []


def test_hunting_query_rejects_unknown_operator():
    from analyzer.hunting.engine import ThreatHuntingEngine
    from analyzer.hunting.models import HuntingQuery

    events = [
        {
            "username": "admin",
            "event_type": "authentication_failure",
        }
    ]

    query = HuntingQuery(
        field="username",
        operator="invalid_operator",
        value="admin",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert results == []


def test_hunting_query_supports_host():
    from analyzer.hunting.engine import ThreatHuntingEngine
    from analyzer.hunting.models import HuntingQuery

    events = [
        {
            "host": "server",
            "event_type": "authentication_failure",
        }
    ]

    query = HuntingQuery(
        field="host",
        operator="equals",
        value="server",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert len(results) == 1
    assert results[0]["host"] == "server" 

def test_hunting_search_limits_results():
    events = [
        {"username": "admin", "failed_attempts": 5},
        {"username": "root", "failed_attempts": 4},
        {"username": "test", "failed_attempts": 3},
    ]

    query = HuntingSearch(
        limit=2,
        sort_by="failed_attempts",
        sort_order="desc",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert len(results) == 2
    assert results[0]["failed_attempts"] == 5
    assert results[1]["failed_attempts"] == 4


def test_hunting_search_sorts_ascending():
    events = [
        {"username": "admin", "failed_attempts": 5},
        {"username": "root", "failed_attempts": 2},
        {"username": "test", "failed_attempts": 8},
    ]

    query = HuntingSearch(
        sort_by="failed_attempts",
        sort_order="asc",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert [event["failed_attempts"] for event in results] == [
        2,
        5,
        8,
    ]


def test_hunting_search_sorts_descending():
    events = [
        {"username": "admin", "failed_attempts": 5},
        {"username": "root", "failed_attempts": 2},
        {"username": "test", "failed_attempts": 8},
    ]

    query = HuntingSearch(
        sort_by="failed_attempts",
        sort_order="desc",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert [event["failed_attempts"] for event in results] == [
        8,
        5,
        2,
    ]

def test_hunting_query_searches_message():
    events = [
        {
            "message": "SSH authentication failure",
            "event_type": "authentication_failure",
        },
        {
            "message": "SSH authentication success",
            "event_type": "authentication_success",
        },
    ]

    query = HuntingQuery(
        field="message",
        operator="contains",
        value="authentication failure",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert len(results) == 1
    assert results[0]["event_type"] == "authentication_failure"


def test_hunting_query_searches_raw_log():
    events = [
        {
            "raw_log": (
                "Sep 15 11:05:21 server sshd[2001]: "
                "Failed password for root from 10.10.10.25"
            ),
            "event_type": "authentication_failure",
        },
        {
            "raw_log": (
                "Sep 15 11:20:10 server sshd[3001]: "
                "Accepted password for root from 10.10.10.30"
            ),
            "event_type": "authentication_success",
        },
    ]

    query = HuntingQuery(
        field="raw_log",
        operator="contains",
        value="10.10.10.25",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert len(results) == 1
    assert results[0]["event_type"] == "authentication_failure"


def test_hunting_contains_is_case_insensitive():
    events = [
        {
            "message": "SSH Authentication Failure",
        }
    ]

    query = HuntingQuery(
        field="message",
        operator="contains",
        value="authentication failure",
    )

    results = ThreatHuntingEngine().search(events, query)

    assert len(results) == 1              