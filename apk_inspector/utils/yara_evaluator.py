from typing import Tuple, List, Dict, Any
from apk_inspector.utils.logger import get_logger

logger = get_logger()

class YaraMatchEvaluator:
    @staticmethod
    def evaluate(
        yara_hits: List[Dict[str, Any]],
        category_score: Dict[str, int],
        tag_score: Dict[str, int],
        severity_score: Dict[str, int]
    ) -> Tuple[int, List[str]]:
        total_score = 0
        reasons = []

        for hit in yara_hits:
            try:
                meta = hit.get("meta", {})
                tags = [t.lower() for t in hit.get("tags", [])]
                rule_id = hit.get("rule", "unknown")
                desc = meta.get("description", rule_id)
                category = meta.get("category", "uncategorized").lower()
                severity = meta.get("severity", "medium").lower()
                confidence = meta.get("confidence", "50")
                impact = meta.get("impact", None)
                family = meta.get("malware_family", None)

                rule_score = 0
                reason_parts = []

                rule_score += category_score.get(category, 0)
                rule_score += severity_score.get(severity, 10)
                rule_score += sum(tag_score.get(tag, 0) for tag in tags)

                try:
                    confidence_val = int(confidence)
                    if confidence_val >= 90:
                        rule_score += 5
                        reason_parts.append("confidence high (90+)")
                except ValueError:
                    logger.warning(f"[YARA] Invalid confidence in rule {rule_id}: {confidence}")
                    reasons.append(f"[WARN] Invalid confidence format: {confidence} for rule {rule_id}")

                if impact:
                    reason_parts.append(f"impact: {impact}")
                if family:
                    reason_parts.append(f"family: {family}")

                reason_line = f"[YARA][{severity.upper()}][{category}] {rule_id}: {desc}"
                if reason_parts:
                    reason_line += f" [{', '.join(reason_parts)}]"

                reasons.append(reason_line)

                unmatched_tags = [tag for tag in tags if tag not in tag_score]
                if unmatched_tags:
                    reasons.append(f"[INFO] Unscored YARA tags: {', '.join(unmatched_tags)}")

                total_score += rule_score

            except Exception as e:
                logger.error(f"[YARA] Failed processing rule hit: {e}")
                reasons.append(f"[ERROR] Failed to evaluate YARA rule: {e}")

        return total_score, reasons
