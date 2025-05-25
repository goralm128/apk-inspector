from dataclasses import dataclass, field
from typing import Callable, List, Dict, Tuple, Optional, Any

@dataclass
class Rule:
    id: str
    description: str
    category: str
    weight: int
    condition: Callable[[dict], bool]
    tags: List[str] = field(default_factory=list)
    cvss: float = 0.0
    severity: str = "medium"

@dataclass
class Verdict:
    score: int
    label: str
    reasons: List[str]

class RuleEngine:
    def __init__(self, rules: List[Rule]):
        self.rules = rules

    def evaluate(
        self,
        events: List[Dict[str, Any]],
        static_info: Optional[Dict[str, Any]] = None,
        yara_hits: Optional[List[Dict[str, Any]]] = None
    ) -> Tuple[str, int, List[str]]:
        score = 0
        reasons = []

        for event in events:
            for rule in self.rules:
                try:
                    if rule.condition(event):
                        score += rule.weight
                        reasons.append(f"[{rule.severity.upper()}] Rule {rule.id}: {rule.description}")
                except Exception as e:
                    reasons.append(f"[WARN] Rule {rule.id} failed to evaluate: {e}")

        if static_info:
            if "SEND_SMS" in static_info.get("manifest_analysis", {}).get("usesPermissions", []):
                score += 15
                reasons.append("[HIGH] Uses SEND_SMS permission")
            if static_info.get("reflection_usage"):
                score += 10
                reasons.append("[MEDIUM] Uses reflection")
            if static_info.get("obfuscation_detected"):
                score += 15
                reasons.append("[HIGH] Obfuscation detected")

        if yara_hits:
            for hit in yara_hits:
                severity = hit.get("meta", {}).get("severity", "medium").lower()
                description = hit.get("meta", {}).get("description", hit.get("rule"))
                severity_weight = {"low": 5, "medium": 10, "high": 20}.get(severity, 10)
                score += severity_weight
                reasons.append(f"[{severity.upper()}] YARA: {description}")

        label = self._label_from_score(score)
        return label, min(score, 100), reasons

    def _label_from_score(self, score: int) -> str:
        if score >= 80:
            return "malicious"
        elif score >= 40:
            return "suspicious"
        return "benign"
