from analyzer.ingestion.unified import UnifiedIngestionPipeline


def test_unified_linux_and_windows_ingestion(tmp_path):

    linux_log = tmp_path / "auth.log"

    linux_log.write_text(
        "Sep 18 10:15:30 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2\n",
        encoding="utf-8",
    )

    windows_log = tmp_path / "windows.log"

    windows_log.write_text(
        "2026 Sep 18 10:20:30 "
        "Failed Windows login for administrator "
        "from 10.0.0.50\n",
        encoding="utf-8",
    )

    pipeline = UnifiedIngestionPipeline()

    events = pipeline.ingest(
        linux_log=linux_log,
        windows_log=windows_log,
    )

    assert len(events) == 2

    assert events[0].source == "linux"
    assert events[0].event_type == "authentication_failure"

    assert events[1].source == "windows"
    assert events[1].event_type == "authentication_failure"


def test_unified_pipeline_sorts_events(tmp_path):

    linux_log = tmp_path / "auth.log"

    linux_log.write_text(
        "Sep 18 10:30:00 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2\n",
        encoding="utf-8",
    )

    windows_log = tmp_path / "windows.log"

    windows_log.write_text(
        "2026 Sep 18 10:10:00 "
        "Failed Windows login for administrator "
        "from 10.0.0.50\n",
        encoding="utf-8",
    )

    pipeline = UnifiedIngestionPipeline()

    events = pipeline.ingest(
        linux_log=linux_log,
        windows_log=windows_log,
    )

    assert len(events) == 2

    assert events[0].source == "windows"
    assert events[1].source == "linux"

def test_unified_linux_windows_network_ingestion(tmp_path):

    linux_log = tmp_path / "auth.log"

    linux_log.write_text(
        "Sep 18 10:10:00 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2\n",
        encoding="utf-8",
    )

    windows_log = tmp_path / "windows.log"

    windows_log.write_text(
        "2026 Sep 18 10:20:00 "
        "Failed Windows login for administrator "
        "from 10.0.0.50\n",
        encoding="utf-8",
    )

    network_log = tmp_path / "network.log"

    network_log.write_text(
        "2026 Sep 18 10:15:00 "
        "Connection attempt from 172.16.0.25 "
        "to port 445\n",
        encoding="utf-8",
    )

    pipeline = UnifiedIngestionPipeline()

    events = pipeline.ingest(
        linux_log=linux_log,
        windows_log=windows_log,
        network_log=network_log,
    )

    assert len(events) == 3

    assert events[0].source == "linux"
    assert events[1].source == "network"
    assert events[2].source == "windows"

    assert events[0].event_type == "authentication_failure"
    assert events[1].event_type == "network_connection_attempt"
    assert events[2].event_type == "authentication_failure"    