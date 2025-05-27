from typing import Dict, Any, List, Tuple

class StaticHeuristicEvaluator:
    @staticmethod
    def evaluate(static_info: Dict[str, Any]) -> Tuple[int, List[str]]:
        score = 0
        reasons = []

        checks = [
            ("SEND_SMS" in static_info.get("manifest_analysis", {}).get("usesPermissions", []),
             15, "[HIGH] Uses SEND_SMS permission"),
            (static_info.get("reflection_usage", False),
             10, "[MEDIUM] Uses reflection"),
            (static_info.get("obfuscation_detected", False),
             15, "[HIGH] Obfuscation detected")
        ]

        for condition, pts, msg in checks:
            if condition:
                score += pts
                reasons.append(msg)

        return score, reasons
