from datetime import datetime, timedelta

from analyzer.detections.service import DetectionService


def test_detection_service_detects_network_scan():
    service = DetectionService()

    base_time = datetime(2026, 9, 20, 10, 0, 0)

    events = []

    for index in range(5):
        events.append(
            {
                "timestamp": base_time + timedelta(minutes=index),
                "event_type": "network_connection_attempt",
                "source_ip": "192.168.1.100",
                "username": None,
                "ip": "192.168.1.100",
                "host": "test-host",
                "message": f"Connection attempt {index + 1}",
                "raw_log": "",
                "source": "network",
            }
        )

    alerts = service.detect(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "DET-NET-001"
    assert alerts[0]["event_count"] == 5