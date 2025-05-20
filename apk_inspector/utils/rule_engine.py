import yaml
from dataclasses import dataclass, field
from typing import Callable, List, Any
from pathlib import Path

@dataclass
class Rule:
    id: str
    description: str
    category: str
    weight: int
    condition: Callable[[dict], bool]
    tags: List[str] = field(default_factory=list)
    cvss: float = 0.0
    severity: str = "medium"  # low | medium | high

@dataclass
class Verdict:
    score: int
    label: str
    reasons: List[str]

class RuleEngine:
    def __init__(self, rules: List[Rule]):
        self.rules = rules

    def evaluate(self, events: List[dict]) -> Verdict:
        total_score = 0
        reasons = set()

        for event in events:
            for rule in self.rules:
                try:
                    if rule.condition(event):
                        total_score += rule.weight
                        reasons.add(f"[{rule.category}] {rule.description}")
                except Exception as e:
                    print(f"[WARN] Rule {rule.id} failed: {e}")

        label = (
            "malicious" if total_score > 10 else
            "suspicious" if total_score >= 6 else
            "benign"
        )
        return Verdict(score=total_score, label=label, reasons=list(reasons))

# Secure eval with a limited scope
def safe_lambda(condition: str) -> Callable[[dict], bool]:
    def func(event):
        return eval(condition, {"__builtins__": {}}, {"event": event})
    return func

# YAML Loader
def load_rules_from_yaml(yaml_path: Path) -> List[Rule]:
    with yaml_path.open(encoding="utf-8") as f:
        raw_rules = yaml.safe_load(f)

    rules = []
    for entry in raw_rules:
       rules.append(Rule(
        id=entry["id"],
        description=entry["description"],
        category=entry["category"],
        weight=entry["weight"],
        condition=safe_lambda(entry["condition"]),
        tags=entry.get("tags", []),
        cvss=entry.get("cvss", 0.0),
        severity=entry.get("severity", "medium"),
    ))

    return rules
