from analyzer.ingestion.pipeline import LinuxIngestionPipeline


def test_auth_log_is_converted_to_detection_events(tmp_path):

    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Sep 18 10:15:30 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2\n"
        "Sep 18 10:16:30 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2\n"
        "Sep 18 10:17:30 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2\n"
        "Sep 18 10:20:30 server sshd[1234]: "
        "Accepted password for admin from 192.168.1.50 port 22 ssh2\n",
        encoding="utf-8",
    )

    pipeline = LinuxIngestionPipeline()

    events = pipeline.ingest(log_file)

    assert len(events) == 4

    failed_events = [
        event
        for event in events
        if event["event_type"] == "authentication_failure"
    ]

    successful_events = [
        event
        for event in events
        if event["event_type"] == "authentication_success"
    ]

    assert len(failed_events) == 3
    assert len(successful_events) == 1

    assert all(
        event["ip"] == "192.168.1.50"
        for event in events
    )

    assert all(
        event["username"] == "admin"
        for event in events
    )