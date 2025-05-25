from typing import List, Dict, Any

class VerdictEngine:
    def __init__(self):
        self.severity_weights = {
            "low": 10,
            "moderate": 25,
            "high": 40
        }
        self.risk_weights = {
            "low": 5,
            "moderate": 15,
            "high": 30
        }

    def score_yara_matches(self, matches: List[Dict[str, Any]]) -> int:
        score = 0
        for m in matches:
            severity = m.get("meta", {}).get("severity", "low").lower()
            score += self.severity_weights.get(severity, 0)
        return score

    def score_dynamic_events(self, events: List[Dict[str, Any]]) -> int:
        score = 0
        for e in events:
            risk = e.get("risk_level", "low").lower()
            score += self.risk_weights.get(risk, 0)
        return score

    def score_static_flags(self, static: Dict[str, Any]) -> (int, List[str]):
        score = 0
        reasons = []

        if "SEND_SMS" in str(static.get("dangerous_permissions", [])):
            score += 15
            reasons.append("Uses dangerous permission: SEND_SMS")
        if static.get("certificate", {}).get("debug_cert"):
            score += 5
            reasons.append("Uses debug certificate")

        return score, reasons

    def evaluate(self, events: List[Dict[str, Any]],
                 yara_hits: List[Dict[str, Any]],
                 static: Dict[str, Any] = None) -> (str, int, List[str]):

        score = 0
        reasons = []

        score += self.score_yara_matches(yara_hits)
        score += self.score_dynamic_events(events)

        static_score, static_reasons = self.score_static_flags(static or {})
        score += static_score
        reasons.extend(static_reasons)

        for e in events:
            if e.get("risk_level") == "high":
                reasons.append(f"High-risk event: {e.get('event')} → {e.get('source')}")

        for match in yara_hits:
            reasons.append(f"Matched YARA rule: {match.get('rule')}")

        label = "malicious" if score >= 80 else "suspicious" if score >= 40 else "benign"
        return label, min(score, 100), reasons
