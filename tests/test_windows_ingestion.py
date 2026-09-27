from datetime import datetime

from analyzer.ingestion.windows import WindowsEventParser


def test_failed_windows_login():

    parser = WindowsEventParser()

    line = (
        "2026 Sep 18 11:15:30 "
        "Failed Windows login for administrator "
        "from 10.0.0.50"
    )

    event = parser.parse_line(line)

    assert event is not None
    assert event.source == "windows"
    assert event.event_type == "authentication_failure"
    assert event.username == "administrator"
    assert event.source_ip == "10.0.0.50"
    assert event.host is None


def test_successful_windows_login():

    parser = WindowsEventParser()

    line = (
        "2026 Sep 18 11:20:30 "
        "Successful Windows login for administrator "
        "from 10.0.0.50"
    )

    event = parser.parse_line(line)

    assert event is not None
    assert event.source == "windows"
    assert event.event_type == "authentication_success"
    assert event.username == "administrator"
    assert event.source_ip == "10.0.0.50"
    assert event.host is None


def test_unknown_windows_event():

    parser = WindowsEventParser()

    line = (
        "2026 Sep 18 11:25:30 "
        "Windows service started successfully"
    )

    event = parser.parse_line(line)

    assert event is None


def test_windows_timestamp():

    parser = WindowsEventParser()

    line = (
        "2026 Sep 18 11:30:45 "
        "Failed Windows login for admin "
        "from 192.168.1.25"
    )

    event = parser.parse_line(line)

    assert event is not None
    assert isinstance(event.timestamp, datetime)
    assert event.timestamp.year == 2026
    assert event.timestamp.month == 9
    assert event.timestamp.day == 18