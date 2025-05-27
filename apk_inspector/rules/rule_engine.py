from dataclasses import dataclass, field
from typing import Callable, List, Dict, Tuple, Optional, Any
from apk_inspector.analysis.yara_analyzer import YaraMatchEvaluator
from apk_inspector.heuristics.static_heuristics import StaticHeuristicEvaluator


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
    MALICIOUS_THRESHOLD = 80
    SUSPICIOUS_THRESHOLD = 40

    CATEGORY_SCORE = {
        "crypto_usage": 10,
        "dex_loading": 15,
        "native_injection": 20,
        "network_exfiltration": 25,
        "malicious_behavior": 30,
        "sensitive_string": 10,
        "system_behavior": 15,
        "overlay_abuse": 15,
        "accessibility_abuse": 15,
        "reflection": 10
    }

    TAG_SCORE = {
        # UI/Permission Abuse
        "overlay": 10,
        "accessibility": 10,
        "clickjacking": 10,
        "system_alert": 10,
        "phishing": 15,

        # Code & Runtime Behavior
        "dex": 10,
        "code_injection": 15,
        "jni": 10,
        "hooking": 15,
        "libc": 10,
        "native": 10,
        "frida": 15,
        "reflection": 10,
        "automation": 15,
        "obfuscation": 10,
        "entropy": 10,

        # Privilege Abuse / Root Bypass
        "su": 15,
        "root": 15,

        # Exfiltration & Network
        "c2": 20,
        "http": 10,
        "dns": 10,
        "dropzone": 10,
        "upload": 10,
        "exfiltration": 20,

        # Crypto & Sensitive Data
        "crypto": 10,
        "base64": 5,
        "short_key": 15,
        "weak_key": 15,
        "ecb": 20,
        "iv": 10,
        "token": 10,
        "auth": 10,
        "jwt": 10,
        "key": 10,

      # Evasion / Other
        "evasion": 10,
        "xor": 10,
        "keylogger": 20
    }

    SEVERITY_SCORE = {
        "low": 5,
        "medium": 10,
        "high": 20
    }

    def __init__(self, rules: List[Rule]):
        self.rules = rules

    def _evaluate_dynamic(self, events: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
        score = 0
        reasons = []

        for event in events:
            for rule in self.rules:
                try:
                    if rule.condition(event):
                        score += rule.weight
                        reasons.append(f"[{rule.severity.upper()}] Rule {rule.id}: {rule.description}")
                except Exception as e:
                    reasons.append(f"[WARN] Rule {rule.id} failed: {e}")
        return score, reasons
    
    def _label_from_score(self, score: int) -> str:
        if score >= self.MALICIOUS_THRESHOLD:
            return "malicious"
        elif score >= self.SUSPICIOUS_THRESHOLD:
            return "suspicious"
        return "benign"

    def evaluate(
        self,
        events: List[Dict[str, Any]],
        static_info: Optional[Dict[str, Any]] = None,
        yara_hits: Optional[List[Dict[str, Any]]] = None
    ) -> Tuple[str, int, List[str]]:
        score = 0
        reasons = []

        # 1. Evaluate dynamic rules
        dynamic_score, dynamic_reasons = self._evaluate_dynamic(events)
        score += dynamic_score
        reasons.extend(dynamic_reasons)

        # 2. Evaluate static heuristics
        if static_info:
            static_score, static_reasons = StaticHeuristicEvaluator.evaluate(static_info)
            score += static_score
            reasons.extend(static_reasons)

        # 3. Evaluate YARA metadata
        if yara_hits:
            yara_score, yara_reasons = YaraMatchEvaluator.evaluate(yara_hits, self.CATEGORY_SCORE, self.TAG_SCORE, self.SEVERITY_SCORE)
            score += yara_score
            reasons.extend(yara_reasons)

        return self._label_from_score(score), min(score, 100), reasons

        
