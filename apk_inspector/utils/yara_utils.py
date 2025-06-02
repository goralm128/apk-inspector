from typing import Tuple, List, Dict, Any
from apk_inspector.reports.models import YaraMatch
from apk_inspector.utils.logger import get_logger


def clean_yara_match(match: Any, enable_logging: bool = True) -> Tuple[List[str], Dict[str, Any]]:
    """
    Ensures YARA match fields are consistently structured and safe to serialize.

    Args:
        match (Any): YARA match object with `tags` and `meta` attributes.
        enable_logging (bool): Whether to log type mismatches.

    Returns:
        Tuple[List[str], Dict[str, Any]]: Cleaned (tags, meta) tuple
    """
    rule_name = getattr(match, 'rule', 'unknown')

    # --- Clean tags ---
    raw_tags = getattr(match, 'tags', [])
    if isinstance(raw_tags, list):
        tags = [str(tag) for tag in raw_tags]
    else:
        if enable_logging:
            logger.warning(f"[YARA:{rule_name}] Unexpected tag format: {raw_tags}")
        tags = [str(raw_tags)]

    # --- Clean meta ---
    raw_meta = getattr(match, 'meta', {})
    if isinstance(raw_meta, dict):
        meta = {}
        for k, v in raw_meta.items():
            try:
                # Convert bytes to string, or fallback to repr()
                if isinstance(v, bytes):
                    meta[k] = v.decode('utf-8', errors='replace')
                else:
                    meta[k] = v
            except Exception as e:
                if enable_logging:
                    logger.warning(f"[YARA:{rule_name}] Failed to clean meta[{k}]: {e}")
                meta[k] = repr(v)
    else:
        if enable_logging:
            logger.warning(f"[YARA:{rule_name}] Unexpected meta format: {raw_meta}")
        meta = {}

    return tags, meta

def convert_matches(matches: List[YaraMatch]) -> List[Dict[str, Any]]:
    return [m.to_dict() for m in matches]

def serialize_yara_strings(strings) -> List[Tuple[int, str, str]]:
    serialized = []
    for offset, identifier, data in strings:
        if isinstance(data, bytes):
            try:
                data_str = data.decode("utf-8", errors="replace")  # Replace undecodable bytes
            except Exception:
                data_str = data.hex()  # Fallback to hex if decode fails badly
        else:
            data_str = str(data)
        serialized.append((offset, identifier, data_str))
    return serialized

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
