from datetime import datetime

from analyzer.ingestion.linux import LinuxAuthLogParser


def test_failed_ssh_login():
    parser = LinuxAuthLogParser()

    line = (
        "Sep 18 10:15:30 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2"
    )

    event = parser.parse_line(line)

    assert event is not None
    assert event.source == "linux"
    assert event.event_type == "authentication_failure"
    assert event.username == "admin"
    assert event.source_ip == "192.168.1.50"
    assert event.raw_log == line
    assert event.host == "server"


def test_invalid_user_ssh_login():
    parser = LinuxAuthLogParser()

    line = (
        "Sep 18 10:16:30 server sshd[1234]: "
        "Failed password for invalid user hacker from 10.0.0.25 port 22 ssh2"
    )

    event = parser.parse_line(line)

    assert event is not None
    assert event.event_type == "authentication_failure"
    assert event.username == "hacker"
    assert event.source_ip == "10.0.0.25"


def test_successful_ssh_login():
    parser = LinuxAuthLogParser()

    line = (
        "Sep 18 10:20:30 server sshd[1234]: "
        "Accepted password for bharath from 192.168.1.100 port 22 ssh2"
    )

    event = parser.parse_line(line)

    assert event is not None
    assert event.source == "linux"
    assert event.event_type == "authentication_success"
    assert event.username == "bharath"
    assert event.source_ip == "192.168.1.100"
    assert event.host == "server"


def test_unknown_log_is_ignored():
    parser = LinuxAuthLogParser()

    line = (
        "Sep 18 10:25:30 server systemd[1]: "
        "Started some unrelated service"
    )

    event = parser.parse_line(line)

    assert event is None


def test_event_timestamp():
    parser = LinuxAuthLogParser()

    line = (
        "Sep 18 10:30:45 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2"
    )

    event = parser.parse_line(line)

    assert event is not None
    assert isinstance(event.timestamp, datetime)
    assert event.timestamp.month == 9
    assert event.timestamp.day == 18
    assert event.timestamp.hour == 10
    assert event.timestamp.minute == 30
    assert event.timestamp.second == 45

def test_parse_file(tmp_path):
    parser = LinuxAuthLogParser()

    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Sep 18 10:15:30 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2\n"
        "Sep 18 10:20:30 server sshd[1234]: "
        "Accepted password for bharath from 192.168.1.100 port 22 ssh2\n"
        "Sep 18 10:25:30 server systemd[1]: "
        "Started unrelated service\n",
        encoding="utf-8",
    )

    events = parser.parse_file(log_file)

    assert len(events) == 2

    assert events[0].event_type == "authentication_failure"
    assert events[0].source_ip == "192.168.1.50"

    assert events[1].event_type == "authentication_success"
    assert events[1].username == "bharath"    