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

    def evaluate(
        self,
        events: List[Dict[str, Any]],
        static_info: Optional[Dict[str, Any]] = None,
        yara_hits: Optional[List[Dict[str, Any]]] = None
    ) -> Tuple[str, int, List[str]]:
        score = 0
        reasons = []

        # Dynamic event-based rule matching
        for event in events:
            for rule in self.rules:
                try:
                    if rule.condition(event):
                        score += rule.weight
                        reasons.append(f"[{rule.severity.upper()}] Rule {rule.id}: {rule.description}")
                except Exception as e:
                    reasons.append(f"[WARN] Rule {rule.id} failed: {e}")

        # Static analysis heuristics
        if static_info:
            static_checks = [
                ("SEND_SMS" in static_info.get("manifest_analysis", {}).get("usesPermissions", []),
                 15, "[HIGH] Uses SEND_SMS permission"),
                (static_info.get("reflection_usage", False),
                 10, "[MEDIUM] Uses reflection"),
                (static_info.get("obfuscation_detected", False),
                 15, "[HIGH] Obfuscation detected")
            ]
            for condition, pts, msg in static_checks:
                if condition:
                    score += pts
                    reasons.append(msg)

        # YARA-based evaluation
        if yara_hits:
            for hit in yara_hits:
                meta = hit.get("meta", {})
                tags = hit.get("tags", [])
                tags = [t.lower() for t in tags]

                rule_id = hit.get("rule", "unknown")
                desc = meta.get("description", rule_id)

                category = meta.get("category", "uncategorized").lower()
                severity = meta.get("severity", "medium").lower()
                tags = [t.lower() for t in hit.get("tags", [])]

                # Scoring
                score += self.CATEGORY_SCORE.get(category, 0)
                score += self.SEVERITY_SCORE.get(severity, 10)
                score += sum(self.TAG_SCORE.get(tag, 0) for tag in tags)

                # Confidence bonus
                try:
                    confidence = int(meta.get("confidence", 50))
                    if confidence >= 90:
                        score += 5
                except ValueError:
                    reasons.append(f"[WARN] Invalid confidence format in rule: {rule_id}")

                # Report unscored tags (informational)
                unmatched_tags = [tag for tag in tags if tag not in self.TAG_SCORE]
                if unmatched_tags:
                    reasons.append(f"[INFO] Unscored YARA tags: {', '.join(unmatched_tags)}")

                reasons.append(f"[YARA][{severity.upper()}][{category}] {rule_id}: {desc}")

        label = self._label_from_score(score)
        return label, min(score, 100), reasons

    def _label_from_score(self, score: int) -> str:
        if score >= self.MALICIOUS_THRESHOLD:
            return "malicious"
        elif score >= self.SUSPICIOUS_THRESHOLD:
            return "suspicious"
        return "benign"
