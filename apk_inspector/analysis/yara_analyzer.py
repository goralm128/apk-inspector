from typing import Tuple, List, Dict, Any
import logging

class YaraMatchEvaluator:
    @staticmethod
    def evaluate(
        yara_hits: List[Dict[str, Any]],
        category_score: Dict[str, int],
        tag_score: Dict[str, int],
        severity_score: Dict[str, int]
    ) -> Tuple[int, List[str]]:
        score = 0
        reasons = []

        for hit in yara_hits:
            meta = hit.get("meta", {})
            tags = [t.lower() for t in hit.get("tags", [])]
            rule_id = hit.get("rule", "unknown")
            desc = meta.get("description", rule_id)
            category = meta.get("category", "uncategorized").lower()
            severity = meta.get("severity", "medium").lower()

            score += category_score.get(category, 0)
            score += severity_score.get(severity, 10)
            score += sum(tag_score.get(tag, 0) for tag in tags)

            try:
                confidence = int(meta.get("confidence", 50))
                if confidence >= 90:
                    score += 5
            except ValueError:
                reasons.append(f"[WARN] Invalid confidence in YARA: {rule_id}")

            unmatched_tags = [tag for tag in tags if tag not in tag_score]
            if unmatched_tags:
                reasons.append(f"[INFO] Unscored YARA tags: {', '.join(unmatched_tags)}")

            reasons.append(f"[YARA][{severity.upper()}][{category}] {rule_id}: {desc}")

        return score, reasons
