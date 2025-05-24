import yaml
from dataclasses import dataclass, field
from typing import Callable, List, Dict, Tuple, Optional, Any
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
    def __init__(self, rules):
        self.rules = rules

    def evaluate(
        self,
        events: List[Dict[str, Any]],
        static_info: Optional[Dict[str, Any]] = None,
        yara_hits: Optional[List[Dict[str, Any]]] = None
    ) -> Tuple[str, int, List[str]]:
        verdict = "benign"
        score = 0
        reasons = []

        # Dummy example: count number of events or static/yara-based logic
        if static_info and static_info.get("manifest_analysis", {}).get("usesPermissions"):
            score += 1
            reasons.append("Uses suspicious permissions")

        if yara_hits:
            matched_files = len(yara_hits)
            if matched_files > 0:
                score += matched_files
                reasons.append(f"YARA matched {matched_files} files")

        if score >= 5:
            verdict = "malicious"
        elif score > 0:
            verdict = "suspicious"

        return verdict, score, reasons

def safe_lambda(condition: str) -> Callable[[dict], bool]:
    def func(event):
        return eval(condition, {"__builtins__": {}}, {"event": event})
    return func

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
