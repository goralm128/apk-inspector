from apk_inspector.rules.rule_engine import load_rules_from_yaml
from apk_inspector.config.defaults import DEFAULT_RULES_PATH

def test_yaml_rules_load():
    rules = load_rules_from_yaml(DEFAULT_RULES_PATH)
    assert len(rules) >= 1
    assert rules[0].id.startswith("R")
    assert callable(rules[0].condition)
