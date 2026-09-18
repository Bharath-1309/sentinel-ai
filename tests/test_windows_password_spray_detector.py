from datetime import datetime

from analyzer.windows_password_spray_detector import (
    WindowsPasswordSprayDetector
)


def test_windows_password_spraying_detection():
    detector = WindowsPasswordSprayDetector()

    alert = detector.detect(
        source_ip="192.168.1.60",
        username_attempts={
            "administrator",
            "john",
            "alice"
        },
        timestamp=datetime.now()
    )

    assert alert is not None
    assert alert.type == "Windows Password Spraying"
    assert alert.ip == "192.168.1.60"
    assert alert.failed_attempts == 3
    assert alert.successful_login is False
    assert alert.risk == "HIGH"


def test_windows_password_spraying_below_threshold():
    detector = WindowsPasswordSprayDetector()

    alert = detector.detect(
        source_ip="192.168.1.60",
        username_attempts={
            "administrator",
            "john"
        },
        timestamp=datetime.now()
    )

    assert alert is None