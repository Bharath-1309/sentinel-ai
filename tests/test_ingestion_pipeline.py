from analyzer.ingestion.pipeline import LinuxIngestionPipeline


def test_linux_ingestion_pipeline(tmp_path):

    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Sep 18 10:15:30 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2\n"
        "Sep 18 10:16:30 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2\n"
        "Sep 18 10:20:30 server sshd[1234]: "
        "Accepted password for admin from 192.168.1.50 port 22 ssh2\n",
        encoding="utf-8",
    )

    pipeline = LinuxIngestionPipeline()

    events = pipeline.ingest(log_file)

    assert len(events) == 3

    assert events[0]["event_type"] == "authentication_failure"
    assert events[0]["ip"] == "192.168.1.50"
    assert events[0]["username"] == "admin"

    assert events[2]["event_type"] == "authentication_success"