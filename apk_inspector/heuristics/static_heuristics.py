from typing import Dict, Any, List, Tuple

class StaticHeuristicEvaluator:
    SUSPICIOUS_STRING_SCORE = {
        "aws_access_key": (20, "[HIGH] AWS access key"),
        "bearer_token": (15, "[HIGH] Bearer token found"),
        "base64_string": (3, "[INFO] Base64-like string (possible encoding)"),
        "hex_string": (10, "[MEDIUM] Hex string detected"),
        "ip_address": (10, "[MEDIUM] Hardcoded IP address"),
        "url_http": (2, "[INFO] Insecure HTTP URL found"),
        "url_https": (5, "[LOW] HTTPS URL found")
    }

    @staticmethod
    def evaluate(static_info: Dict[str, Any]) -> Tuple[int, List[str]]:
        score = 0
        reasons = []

        # --- Permission & basic heuristics ---
        checks = [
            ("SEND_SMS" in static_info.get("manifest_analysis", {}).get("permissions", []),
             15, "[HIGH] Uses SEND_SMS permission"),
            (static_info.get("reflection_usage", False),
             10, "[MEDIUM] Uses reflection"),
            (static_info.get("obfuscation_detected", False),
             15, "[HIGH] Obfuscation detected"),
        ]

        for condition, pts, msg in checks:
            if condition:
                score += pts
                reasons.append(msg)

        # --- Dangerous Permissions ---
        for perm in static_info.get("manifest_analysis", {}).get("dangerous_permissions", []):
            reasons.append(f"[MEDIUM] Uses dangerous permission: {perm}")
            score += 10

        # --- Suspicious Strings ---
        for string in static_info.get("string_matches", []):
            label = string.get("type")
            match = string.get("match")
            entropy = string.get("entropy", 0.0)

            if label in StaticHeuristicEvaluator.SUSPICIOUS_STRING_SCORE:
                pts, description = StaticHeuristicEvaluator.SUSPICIOUS_STRING_SCORE[label]

                # Optional entropy threshold (for base64 or generic encoding)
                if label == "base64_string" and entropy < 3.5:
                    continue  # skip low-entropy "base64" strings

                score += pts
                reasons.append(f"{description}: {match[:40]}...")  # Truncate long matches

        # --- strings.xml Issues ---
        for issue in static_info.get("strings_xml_issues", []):
            match = issue.get("match", "")
            reason = issue.get("reason", "Sensitive string in strings.xml")
            score += 15 # Default score for strings.xml issues
            reasons.append(f"[MEDIUM] {reason}: {match[:40]}...")

        # --- Logging Sensitive Data ---
        for entry in static_info.get("log_leaks", []):
            hint = entry.get("hint", "unknown")
            file = entry.get("file", "")
            score += 5
            reasons.append(f"[MEDIUM] Logs sensitive data ({hint}) in {file}")


        return score, reasons