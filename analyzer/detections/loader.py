from pathlib import Path

import yaml

from .models import DetectionRule


class DetectionRuleLoader:

    def __init__(self, rules_directory: str | Path):
        self.rules_directory = Path(rules_directory)

    def load_rule(self, rule_file: str | Path) -> DetectionRule:

        path = Path(rule_file)

        if not path.is_absolute():
            path = self.rules_directory / path

        with open(
            path,
            "r",
            encoding="utf-8",
        ) as file:

            data = yaml.safe_load(file)

        return DetectionRule(
            rule_id=data["rule_id"],
            name=data["name"],
            description=data["description"],
            event_type=data["event_type"],
            threshold=data["threshold"],
            window_minutes=data["window_minutes"],
            severity=data["severity"],
            mitre_technique=data["mitre_technique"],
            mitre_tactic=data["mitre_tactic"],
            enabled=data.get("enabled", True),
        )

    def load_all(self) -> list[DetectionRule]:

        rules = []

        for rule_file in sorted(
            self.rules_directory.glob("*.yaml")
        ):
            rules.append(
                self.load_rule(rule_file)
            )

        return rules