import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.log_analyzer import analyze_logs


def test_ssh_brute_force_detection():
    alerts = analyze_logs()

    assert len(alerts) == 2
    assert alerts[0]["timestamp"] == "Sep 15 10:21:09"
    assert alerts[1]["timestamp"] == "Sep 15 11:05:27"

    assert alerts[0]["type"] == "SSH Brute Force"
    assert alerts[0]["risk"] == "CRITICAL"

    assert alerts[1]["type"] == "SSH Brute Force"
    assert alerts[1]["risk"] == "MEDIUM"

def test_suspicious_root_login():
    analyze_logs()