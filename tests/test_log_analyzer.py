import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.log_analyzer import analyze_logs


def test_ssh_brute_force_detection():
    alerts = analyze_logs()

    assert len(alerts) == 2

    assert alerts[0]["type"] == "SSH Brute Force"
    assert alerts[0]["risk"] == "HIGH"

    assert alerts[1]["type"] == "SSH Brute Force"
    assert alerts[1]["risk"] == "MEDIUM"