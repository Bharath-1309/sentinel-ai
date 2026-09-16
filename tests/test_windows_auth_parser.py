from analyzer.log_analyzer import parse_windows_auth_line


def test_parse_windows_auth_line():
    line = (
        "2026 Sep 16 10:00:01 "
        "Failed Windows login for administrator "
        "from 192.168.1.50"
    )

    result = parse_windows_auth_line(line)

    assert result is not None
    assert result["username"] == "administrator"
    assert result["ip"] == "192.168.1.50"