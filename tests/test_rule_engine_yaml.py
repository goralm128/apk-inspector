import pytest
from pathlib import Path
from apk_inspector.rules.rule_engine import RuleEngine, load_rules_from_yaml

# Sample mock event that should match a rule
mock_event_sensitive = {
    "event": "read",
    "path": "/data/data/com.example/token.txt",
    "classification": "sensitive"
}

mock_event_config = {
    "event": "read",
    "path": "/sdcard/settings.json",
    "classification": "config"
}

def test_load_rules_from_yaml_valid():
    yaml_path = Path("rule_configs/rules.yaml")
    rules = load_rules_from_yaml(yaml_path)

    assert isinstance(rules, list)
    assert all(rule.id and rule.condition for rule in rules)

def test_rule_engine_applies_yaml_rules_correctly():
    rules = load_rules_from_yaml(Path("rule_configs/rules.yaml"))
    engine = RuleEngine(rules)

    verdict = engine.evaluate([mock_event_sensitive, mock_event_config])

    assert isinstance(verdict.score, int)
    assert verdict.score > 0
    assert verdict.label in {"benign", "suspicious", "malicious"}
    assert any("Accessed" in r for r in verdict.reasons)

def test_rule_severity_tags():
    rules = load_rules_from_yaml(Path("rule_configs/rules.yaml"))
    severities = set(rule.severity for rule in rules)

    assert "low" in severities or "medium" in severities or "high" in severities
