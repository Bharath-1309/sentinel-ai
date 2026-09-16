from datetime import datetime

from analyzer.windows_auth_detector import WindowsAuthDetector


def test_windows_auth_brute_force_detection():
    detector = WindowsAuthDetector()

    alert = detector.detect_brute_force(
        username="administrator",
        source_ip="192.168.1.50",
        failed_attempts=5,
        timestamp=datetime.now()
    )

    assert alert is not None
    assert alert.type == "Windows Authentication Brute Force"
    assert alert.username == "administrator"
    assert alert.source_ip == "192.168.1.50"
    assert alert.failed_attempts == 5
    assert alert.risk == "HIGH"


def test_windows_auth_brute_force_not_detected_below_threshold():
    detector = WindowsAuthDetector()

    alert = detector.detect_brute_force(
        username="administrator",
        source_ip="192.168.1.50",
        failed_attempts=2,
        timestamp=datetime.now()
    )

    assert alert is None

def test_windows_auth_brute_force_critical_risk():
    detector = WindowsAuthDetector()

    alert = detector.detect_brute_force(
        username="administrator",
        source_ip="10.10.10.50",
        failed_attempts=10,
        timestamp=datetime.now()
    )

    assert alert is not None
    assert alert.risk == "CRITICAL"    