from datetime import datetime

from analyzer.ingestion.network import NetworkLogParser


def test_network_connection_attempt():

    parser = NetworkLogParser()

    line = (
        "2026 Sep 18 12:15:30 "
        "Connection attempt from 192.168.1.50 "
        "to port 445"
    )

    event = parser.parse_line(line)

    assert event is not None
    assert event.source == "network"
    assert event.event_type == "network_connection_attempt"
    assert event.source_ip == "192.168.1.50"
    assert event.username is None


def test_network_port_in_message():

    parser = NetworkLogParser()

    line = (
        "2026 Sep 18 12:20:30 "
        "Connection attempt from 10.0.0.25 "
        "to port 3389"
    )

    event = parser.parse_line(line)

    assert event is not None
    assert "3389" in event.message


def test_unknown_network_event():

    parser = NetworkLogParser()

    line = (
        "2026 Sep 18 12:25:30 "
        "Network interface started"
    )

    event = parser.parse_line(line)

    assert event is None


def test_network_timestamp():

    parser = NetworkLogParser()

    line = (
        "2026 Sep 18 12:30:45 "
        "Connection attempt from 10.0.0.25 "
        "to port 22"
    )

    event = parser.parse_line(line)

    assert event is not None
    assert isinstance(event.timestamp, datetime)
    assert event.timestamp.year == 2026
    assert event.timestamp.month == 9
    assert event.timestamp.day == 18