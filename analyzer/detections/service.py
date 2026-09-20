from pathlib import Path

from .loader import DetectionRuleLoader
from .rule_engine import DetectionRuleEngine


class DetectionService:
    def __init__(self, rules_directory=None):
        if rules_directory is None:
            rules_directory = Path(__file__).parent / "rules"

        self.loader = DetectionRuleLoader(rules_directory)
        self.engine = DetectionRuleEngine()

    def detect(self, events):
        rules = self.loader.load_all()

        alerts = []

        for rule in rules:
            rule_alerts = self.engine.evaluate(rule, events)
            alerts.extend(rule_alerts)

        return alerts
