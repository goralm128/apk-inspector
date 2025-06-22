from typing import Dict, Any, List, Tuple

class StaticHeuristicEvaluator:
    
    SUSPICIOUS_STRING_SCORE = {
        "aws_access_key": (15, "[HIGH] AWS access key"),
        "bearer_token": (12, "[HIGH] Bearer token found"),
        "base64_string": (2, "[INFO] Base64-like string (possible encoding)"),
        "hex_string": (10, "[MEDIUM] Hex string detected"),
        "ip_address": (10, "[MEDIUM] Hardcoded IP address"),
        "url_http": (1, "[INFO] Insecure HTTP URL found"),
        "url_https": (0, "[LOW] HTTPS URL found")
    }

    DANGEROUS_PATTERNS = [
        ({"android.permission.SEND_SMS", "android.permission.RECEIVE_SMS", "android.permission.READ_SMS"},
         "[HIGH] SMS trojan pattern (SEND + RECEIVE + READ_SMS)"),
        ({"android.permission.READ_CONTACTS", "android.permission.INTERNET"},
         "[HIGH] Data exfiltration pattern (CONTACTS + INTERNET)"),
        ({"android.permission.RECORD_AUDIO", "android.permission.INTERNET"},
         "[HIGH] Spyware pattern (RECORD_AUDIO + INTERNET)"),
        ({"android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG"},
         "[MEDIUM] Call log abuse pattern"),
        ({"android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"},
         "[MEDIUM] GPS tracking pattern"),
    ]

    INTENT_WEIGHTS = {
        "ACTION_BOOT_COMPLETED": (10, "[HIGH] Broadcast receiver: BOOT_COMPLETED"),
        "INSTALL_PACKAGES": (8, "[HIGH] Intent to install packages"),
    }

    @staticmethod
    def evaluate(static_info: Dict[str, Any]) -> Tuple[int, List[str]]:
        score = 0
        reasons = []

        manifest = static_info.get("manifest_analysis", {})
        permissions = manifest.get("permissions", [])
        dangerous_permissions = set(manifest.get("dangerous_permissions", []))

        # --- Simple permission & feature flags ---
        if "android.permission.SEND_SMS" in permissions:
            score += 15
            reasons.append("[HIGH] Uses SEND_SMS permission")

        if static_info.get("reflection_usage", False):
            score += 10
            reasons.append("[MEDIUM] Uses reflection")

        if static_info.get("obfuscation_detected", False):
            score += 15
            reasons.append("[HIGH] Obfuscation detected")

        # --- Dangerous Permissions ---
        for perm in dangerous_permissions:
            if perm in {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.CALL_PHONE"}:
                score += 10
                reasons.append(f"[HIGH] High-risk permission: {perm}")
            else:
                score += 5
                reasons.append(f"[LOW] Uses dangerous permission: {perm}")

        # --- Dangerous Patterns ---
        perms_set = set(permissions)
        for pattern, pattern_desc in StaticHeuristicEvaluator.DANGEROUS_PATTERNS:
            if pattern.issubset(perms_set):
                score += 5
                reasons.append(pattern_desc)

        # --- Suspicious Strings ---
        for string in static_info.get("string_matches", []):
            label = string.get("type")
            match = string.get("match", "")
            entropy = string.get("entropy", 0.0)

            if label in StaticHeuristicEvaluator.SUSPICIOUS_STRING_SCORE:
                pts, description = StaticHeuristicEvaluator.SUSPICIOUS_STRING_SCORE[label]
                if label == "base64_string" and entropy < 3.5:
                    continue
                score += pts
                reasons.append(f"{description}: {match[:40]}...")

        # --- strings.xml Issues ---
        for issue in static_info.get("strings_xml_issues", []):
            match = issue.get("match", "")
            reason = issue.get("reason", "Sensitive string in strings.xml")
            score += 15
            reasons.append(f"[MEDIUM] {reason}: {match[:40]}...")

        # --- Log Sensitive Data ---
        for entry in static_info.get("log_leaks", []):
            hint = entry.get("hint", "unknown")
            file = entry.get("file", "")
            score += 5
            reasons.append(f"[MEDIUM] Logs sensitive data ({hint}) in {file}")

        # --- Certificate Checks ---
        if static_info.get("certificate", {}).get("is_testkey", False):
            score += 10
            reasons.append("[HIGH] APK signed with test key")

        # --- DEX Checks ---
        dex_info = static_info.get("dex_info", {})
        if dex_info.get("dex_count", 0) > 1:
            score += 10
            reasons.append("[MEDIUM] Multiple DEX files detected")
        if dex_info.get("max_dex_size_mb", 0) > 10:
            score += 5
            reasons.append("[LOW] Large DEX file (>10 MB)")

        # --- Intent Filters ---
        for intent in static_info.get("intent_filters", []):
            if intent in StaticHeuristicEvaluator.INTENT_WEIGHTS:
                pts, msg = StaticHeuristicEvaluator.INTENT_WEIGHTS[intent]
                score += pts
                reasons.append(msg)

        # --- Final normalization ---
        MAX_RAW_STATIC_SCORE = 60
        capped = min(score, MAX_RAW_STATIC_SCORE)
        normalized_score = int((capped / MAX_RAW_STATIC_SCORE) * 10)

        return normalized_score, reasons
