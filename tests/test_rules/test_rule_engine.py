import pytest
from apk_inspector.rules.rule_engine import Rule, RuleEngine, Verdict


def mock_event(tags=None, classification=None, ip=None, direction=None, bytes=0):
    return {
        "tags": tags or [],
        "classification": classification,
        "address": {"ip": ip} if ip else {},
        "direction": direction,
        "bytes": bytes
    }


def test_rule_matching_single():
    rule = Rule(
    id="R1",
    description="Accessed sensitive file",
    category="data_leak",
    weight=4,
    condition=lambda e: e.get("classification") == "sensitive",
    tags=["privacy", "file"],
    cvss=5.3
)
    engine = RuleEngine([rule])

    events = [mock_event(classification="sensitive")]
    verdict = engine.evaluate(events)

    assert verdict.score == 4
    assert verdict.label == "benign"
    assert "data_leak" in verdict.reasons[0]


def test_rule_combination():
    rules = [
        Rule(id="R1", description="Public IP", category="network", weight=6, condition=lambda e: e["address"]["ip"] == "8.8.8.8"),
        Rule(id="R2", description="Large outbound", category="exfiltration", weight=5, condition=lambda e: e["bytes"] > 10000)
    ]
    engine = RuleEngine(rules)

    events = [mock_event(ip="8.8.8.8", direction="outbound", bytes=12000)]
    verdict = engine.evaluate(events)

    assert verdict.score == 11
    assert verdict.label == "malicious"
    assert len(verdict.reasons) == 2


def test_no_match_returns_benign():
    rule = Rule(
        id="TEST2",
        description="Should not match",
        category="misc",
        weight=10,
        condition=lambda e: False
    )
    engine = RuleEngine([rule])

    events = [mock_event()]
    verdict = engine.evaluate(events)

    assert verdict.score == 0
    assert verdict.label == "benign"
    assert verdict.reasons == []
