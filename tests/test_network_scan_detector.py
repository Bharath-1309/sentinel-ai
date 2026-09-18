from datetime import datetime

from analyzer.network_scan_detector import NetworkScanDetector


def test_network_scan_detection():
    detector = NetworkScanDetector()

    alert = detector.detect(
        source_ip="192.168.1.70",
        target_ports={22, 80, 443, 445, 3389},
        timestamp=datetime.now()
    )

    assert alert is not None
    assert alert.type == "Network Service Scanning"
    assert alert.ip == "192.168.1.70"
    assert alert.failed_attempts == 5
    assert alert.successful_login is False
    assert alert.risk == "HIGH"


def test_network_scan_below_threshold():
    detector = NetworkScanDetector()

    alert = detector.detect(
        source_ip="192.168.1.70",
        target_ports={22, 80, 443},
        timestamp=datetime.now()
    )

    assert alert is None