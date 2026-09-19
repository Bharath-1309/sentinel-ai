from datetime import datetime

from analyzer.credential_dumping_detector import (
    CredentialDumpingDetector
)


def test_credential_dumping_detection():
    detector = CredentialDumpingDetector()

    alert = detector.detect(
        source_ip="192.168.1.80",
        evidence_count=1,
        timestamp=datetime.now(),
        username="administrator"
    )

    assert alert is not None
    assert alert.type == "Credential Dumping"
    assert alert.ip == "192.168.1.80"
    assert alert.username == "administrator"
    assert alert.failed_attempts == 1
    assert alert.successful_login is False
    assert alert.risk == "CRITICAL"


def test_credential_dumping_below_threshold():
    detector = CredentialDumpingDetector()

    alert = detector.detect(
        source_ip="192.168.1.80",
        evidence_count=0,
        timestamp=datetime.now()
    )

    assert alert is None