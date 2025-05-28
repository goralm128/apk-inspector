from typing import Tuple, List, Dict, Any
import logging

logger = logging.getLogger(__name__)

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
                # Normalize YaraMatch object vs dict
                if hasattr(hit, 'meta'):
                    meta = getattr(hit, 'meta', {})
                    tags = [t.lower() for t in getattr(hit, 'tags', [])]
                    rule_id = getattr(hit, 'rule', 'unknown')
                else:
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

                # Score components
                cat_score = category_score.get(category, 0)
                sev_score = severity_score.get(severity, 10)
                tag_scores = sum(tag_score.get(tag, 0) for tag in tags)

                rule_score += cat_score + sev_score + tag_scores

                try:
                    confidence_val = int(confidence)
                    if confidence_val >= 90:
                        rule_score += 5
                        reason_parts.append("confidence high (90+)")
                except ValueError:
                    logger.warning(f"[YARA] Invalid confidence in rule {rule_id}: {confidence}")
                    reasons.append(f"[WARN] Invalid confidence format: {confidence} for rule {rule_id}")

                # Add optional impact or family
                if impact:
                    reason_parts.append(f"impact: {impact}")
                if family:
                    reason_parts.append(f"family: {family}")

                # Compose reason line
                summary = f"{rule_id}: {desc}"
                reason_line = f"[YARA][{severity.upper()}][{category}] {summary} (score: {rule_score})"
                if reason_parts:
                    reason_line += f" [{', '.join(reason_parts)}]"

                reasons.append(reason_line)

                # Check for unused tags
                unmatched_tags = [tag for tag in tags if tag not in tag_score]
                if unmatched_tags:
                    reasons.append(f"[INFO] Unscored YARA tags: {', '.join(unmatched_tags)}")

                total_score += rule_score

            except Exception as e:
                logger.error(f"[YARA] Failed processing rule hit: {e}")
                reasons.append(f"[ERROR] Failed to evaluate YARA rule: {e}")

        return total_score, reasons
