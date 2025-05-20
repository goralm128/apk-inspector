from apk_inspector.utils.rule_engine import load_rules_from_yaml
from pathlib import Path

def test_yaml_rules_load():
    rules = load_rules_from_yaml(Path("rules/rules.yaml"))
    assert len(rules) >= 1
    assert rules[0].id.startswith("R")
    assert callable(rules[0].condition)
