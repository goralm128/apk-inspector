from dataclasses import dataclass, field
from typing import Callable, List, Dict, Tuple, Optional, Any
from apk_inspector.analysis.yara_evaluator import YaraMatchEvaluator
from apk_inspector.heuristics.static_heuristics import StaticHeuristicEvaluator
from apk_inspector.reports.models import Verdict


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
    disabled: bool = False


class RuleEngine:
    MALICIOUS_THRESHOLD = 80
    SUSPICIOUS_THRESHOLD = 40

    PATH_TYPE_SCORE = {
        "sensitive": 20,
        "system_access": 15,
        "obfuscated_write": 10,
        "config": 10,
        "app_storage": 5,
        "general": 0
    }

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

    def _evaluate_dynamic(self, events: List[Dict[str, Any]]) -> Tuple[int, List[str], int, bool]:
        score = 0
        reasons = []
        high_risk_event_count = 0
        network_activity_detected = False

        for event in events:
            triggered_severities = []

            for rule in self.rules:
                if rule.disabled:
                    continue
                try:
                    if rule.condition(event):
                        triggered_severities.append(rule.severity)
                        event.setdefault("metadata", {}).setdefault("triggered_rules", []).append(rule.id)
                        event["metadata"].setdefault("rule_severities", []).append(rule.severity)

                        if rule.cvss > 0:
                            score += int(rule.cvss)
                        else:
                            score += rule.weight + self.SEVERITY_SCORE.get(rule.severity, 0)

                        reasons.append(f"[{rule.severity.upper()}] Rule {rule.id}: {rule.description}")

                except Exception as e:
                    reasons.append(f"[WARN] Rule {rule.id} failed: {e}")

            if any(s in {"high", "critical"} for s in triggered_severities):
                event["metadata"]["risk_level"] = "high"
                high_risk_event_count += 1

            if event.get("metadata", {}).get("category") == "network":
                network_activity_detected = True

            path_type = event.get("path_type")
            if path_type:
                pts = self.PATH_TYPE_SCORE.get(path_type, 0)
                if pts > 0:
                    score += pts
                    reasons.append(f"[DYNAMIC] Accessed {path_type} path: {event.get('path') or event.get('file')}")

        return score, reasons, high_risk_event_count, network_activity_detected

    
    def _label_from_score(self, total_score: int, dynamic_score: int = 0) -> str:
        if total_score >= self.MALICIOUS_THRESHOLD:
            return "malicious"
        elif total_score >= self.SUSPICIOUS_THRESHOLD or dynamic_score >= 30:
            return "suspicious"
        return "benign"

    def evaluate(
        self,
        events: List[Dict[str, Any]],
        static_info: Optional[Dict[str, Any]] = None,
        yara_hits: Optional[List[Dict[str, Any]]] = None
    ) -> Verdict:
        total_score = 0
        reasons = []

        static_score = 0
        if static_info:
            static_score, static_reasons = StaticHeuristicEvaluator.evaluate(static_info)
            static_score = min(static_score, 20)
            reasons.extend([f"[STATIC] {r}" for r in static_reasons])

        dynamic_score, dynamic_reasons, high_risk_events, network_flag = self._evaluate_dynamic(events)
        dynamic_score = min(dynamic_score, 70)
        reasons.extend([f"[DYNAMIC] {r}" for r in dynamic_reasons])

        yara_score = 0
        if yara_hits:
            yara_score, yara_reasons = YaraMatchEvaluator.evaluate(
                yara_hits,
                category_score=self.CATEGORY_SCORE,
                tag_score=self.TAG_SCORE,
                severity_score=self.SEVERITY_SCORE
            )

            yara_score = min(yara_score, 10)
            reasons.extend([f"[YARA] {r}" for r in yara_reasons])

        total_score = static_score + dynamic_score + yara_score
        label = self._label_from_score(total_score, dynamic_score)

        return Verdict(
            score=min(total_score, 100),
            label=label,
            reasons=reasons,
            high_risk_event_count=high_risk_events,
            network_activity_detected=network_flag
        )


            
