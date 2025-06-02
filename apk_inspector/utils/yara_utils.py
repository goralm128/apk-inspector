from typing import Tuple, List, Dict, Any
from apk_inspector.reports.models import YaraMatch
from apk_inspector.utils.logger import get_logger


from typing import Any, List, Tuple, Dict
import logging

logger = logging.getLogger(__name__)


def clean_yara_match(match: Any, enable_logging: bool = True) -> Tuple[List[str], Dict[str, Any]]:
    """
    Normalize YARA match fields for tags and meta attributes.

    Args:
        match (Any): YARA match object.
        enable_logging (bool): Controls logging of anomalies.

    Returns:
        Tuple[List[str], Dict[str, Any]]: (tags, meta)
    """
    rule_name = getattr(match, 'rule', 'unknown')

    # --- Tags ---
    raw_tags = getattr(match, 'tags', [])
    if isinstance(raw_tags, list):
        tags = [str(tag) for tag in raw_tags]
    else:
        tags = [str(raw_tags)]
        if enable_logging:
            logger.warning(f"[YARA:{rule_name}] Unexpected tag format: {raw_tags}")

    # --- Meta ---
    raw_meta = getattr(match, 'meta', {})
    meta = {}
    if isinstance(raw_meta, dict):
        for k, v in raw_meta.items():
            try:
                if isinstance(v, bytes):
                    meta[k] = v.decode("utf-8", errors="replace")
                else:
                    meta[k] = v
            except Exception as e:
                if enable_logging:
                    logger.warning(f"[YARA:{rule_name}] Failed to clean meta[{k}]: {e}")
                meta[k] = repr(v)
    else:
        if enable_logging:
            logger.warning(f"[YARA:{rule_name}] Unexpected meta format: {raw_meta}")

    return tags, meta


def serialize_yara_strings(strings) -> List[Dict[str, Any]]:
    """
    Safely serialize yara.StringMatch objects to JSON-safe format.

    Args:
        strings: List of yara.StringMatch

    Returns:
        List[Dict[str, Any]]
    """
    serialized = []
    for s in strings:
        try:
            # Support both tuple format and object format
            if isinstance(s, tuple) and len(s) == 3:
                offset, identifier, data = s
            else:
                offset = getattr(s, "offset", None)
                identifier = getattr(s, "identifier", "unknown")
                data = getattr(s, "data", b"")

            if data is None:
                data_str = ""
            elif isinstance(data, bytes):
                data_str = data.decode("utf-8", errors="replace")
            else:
                data_str = str(data)

            serialized.append({
                "offset": offset,
                "identifier": identifier,
                "data": data_str
            })

        except Exception as e:
            logger.warning(f"[YARA] Failed to serialize YARA string: {e}")
    return serialized

def convert_matches(matches: List[Any]) -> List[Dict[str, Any]]:
    return [m.to_dict() for m in matches]


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

                rule_score = 0
                rule_score += category_score.get(category, 0)
                rule_score += severity_score.get(severity, 10)
                rule_score += sum(tag_score.get(tag, 0) for tag in tags)

                confidence = meta.get("confidence", "50")
                try:
                    if int(confidence) >= 90:
                        rule_score += 5
                except ValueError:
                    reasons.append(f"[WARN] Invalid confidence in YARA rule: {rule_id}")

                unmatched_tags = [tag for tag in tags if tag not in tag_score]
                if unmatched_tags:
                    reasons.append(f"[INFO] Unscored YARA tags: {', '.join(unmatched_tags)}")

                reasons.append(
                    f"[YARA][{severity.upper()}][{category}] {rule_id}: {desc} (score: {rule_score})"
                )

                total_score += rule_score

            except Exception as e:
                logger.exception(f"[YARA] Failed to evaluate match {hit}: {e}")
                reasons.append(f"[ERROR] Could not process rule '{hit.get('rule', 'unknown')}'")

        return total_score, reasons
