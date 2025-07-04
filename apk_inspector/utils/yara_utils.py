from typing import Tuple, List, Dict, Any
from apk_inspector.reports.yara_match_model import YaraMatchModel
from pydantic import ValidationError
from apk_inspector.utils.logger import get_logger

logger = get_logger()

def build_minimal_yara_models(rule_names: List[str]) -> List[YaraMatchModel]:
    """
    Given a list of raw rule names (e.g., from JSON), return YaraMatchModel stubs
    for evaluation/logging purposes.
    """
    models = []
    for name in rule_names:
        models.append(YaraMatchModel(
            rule=name,
            tags=[name],  # crude fallback
            meta={"source": "json_stub"},
            file="unknown",
            strings=[],
            namespace="default"
        ))
    return models

def ensure_yara_models(matches: List[Any]) -> List[YaraMatchModel]:
    """
    Ensures each item in the list is a YaraMatchModel instance.
    Validates and logs issues with malformed inputs.
    """
    result = []
    for index, raw in enumerate(matches):
        try:
            if isinstance(raw, YaraMatchModel):
                result.append(raw)
            elif isinstance(raw, dict):
                result.append(YaraMatchModel(**raw))
            elif hasattr(raw, "to_dict"):
                result.append(YaraMatchModel(**raw.to_dict()))
            else:
                logger.warning(f"[YARA] Unsupported match type at index {index}: {type(raw)}")
        except ValidationError as ve:
            logger.error(f"[YARA] Validation failed at index {index}: {ve}")
        except Exception as ex:
            logger.exception(f"[YARA] Unexpected error at index {index}: {ex}")
    return result

def serialize_yara_models(models: List[YaraMatchModel]) -> List[Dict[str, Any]]:
    """
    Serializes validated YaraMatchModel instances to plain dicts.
    """
    return [m.model_dump() for m in models]

def clean_yara_match(match: Any, enable_logging: bool = True) -> Tuple[List[str], Dict[str, Any]]:
    """
    Normalize raw YARA match object to extract tags and meta fields.

    Args:
        match (Any): Likely a `yara.Match` object or similar.
        enable_logging (bool): Whether to log format issues.

    Returns:
        Tuple[List[str], Dict[str, Any]]: Cleaned tags and meta dictionary.
    """
    rule_name = getattr(match, 'rule', 'unknown')

    # --- Tags ---
    raw_tags = getattr(match, 'tags', [])
    logger.debug(f"[YARA DEBUG] Raw match.tags: {repr(raw_tags)}")

    if isinstance(raw_tags, (list, tuple, set)):
        tags = [str(tag) for tag in raw_tags]
    else:
        tags = [str(raw_tags)]
        if enable_logging:
            logger.warning(f"[YARA:{rule_name}] Unexpected tag format: {type(raw_tags)}")

    # --- Meta ---
    raw_meta = getattr(match, 'meta', {})
    meta: Dict[str, Any] = {}

    if isinstance(raw_meta, dict):
        for k, v in raw_meta.items():
            try:
                meta[k] = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else v
            except Exception as ex:
                meta[k] = repr(v)
                if enable_logging:
                    logger.warning(f"[YARA:{rule_name}] Failed to clean meta[{k}]: {ex}")
    else:
        if enable_logging:
            logger.warning(f"[YARA:{rule_name}] Unexpected meta format: {type(raw_meta)}")

    return tags, meta


def serialize_yara_strings(strings: List[Any]) -> List[Dict[str, Any]]:
    """
    Converts YARA string matches into JSON-serializable dictionaries.

    Args:
        strings (List[Any]): List of yara.StringMatch or tuple-based matches.

    Returns:
        List[Dict[str, Any]]
    """
    serialized = []
    for s in strings:
        try:
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
        except Exception as ex:
            logger.warning(f"[YARA] Failed to serialize YARA string: {ex}")
    return serialized


def convert_matches(matches: List[Any]) -> List[Dict[str, Any]]:
    logger.warning("[YARA] `convert_matches()` is deprecated. Use `ensure_yara_models()` + `serialize_yara_models()` instead.")
    return serialize_yara_models(ensure_yara_models(matches))

class YaraMatchEvaluator:
    """
    Evaluates validated YARA rule matches using configured scoring dictionaries.
    Returns a score and a list of human-readable reasoning strings.
    """

    @staticmethod
    def evaluate(
        yara_hits: List[Dict[str, Any]],
        category_score: Dict[str, int],
        tag_score: Dict[str, int],
        severity_score: Dict[str, int]
    ) -> Tuple[int, List[str]]:
        total_score = 0
        reasons: List[str] = []
        validated_hits: List[YaraMatchModel] = []

        # --- Validate and Deduplicate Hits by (rule + category + severity) ---
        unique_hit_keys = set()
        for index, hit in enumerate(yara_hits):
            try:
                if isinstance(hit, dict):
                    hit = YaraMatchModel.model_validate(hit)
                elif not isinstance(hit, YaraMatchModel):
                    continue  # skip unsupported types

                key = (hit.rule, hit.meta.get("category", "uncategorized"), hit.meta.get("severity", "medium"))
                if key in unique_hit_keys:
                    continue  # skip duplicates
                unique_hit_keys.add(key)
                validated_hits.append(hit)
            except Exception as ex:
                logger.warning(f"[YARA] Skipping invalid hit at index {index}: {ex}")

        severity_weights = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        severity_sum = 0

        for hit in validated_hits:
            rule_id = hit.rule
            tags = [t.lower() for t in hit.tags]
            meta = hit.meta or {}

            desc = str(meta.get("description", rule_id))
            category = str(meta.get("category", "uncategorized")).lower()
            severity = str(meta.get("severity", "medium")).lower()
            confidence = str(meta.get("confidence", "50"))

            category_pts = category_score.get(category, 0)
            severity_pts = severity_score.get(severity, 10)
            tag_pts = sum(tag_score.get(tag, 0) for tag in tags)

            rule_score = category_pts + severity_pts + tag_pts
            try:
                if int(confidence) >= 90:
                    rule_score += 5
            except ValueError:
                pass

            total_score += rule_score
            severity_sum += severity_weights.get(severity, 2)

            reasons.append(
                f"[YARA][{severity.upper()}][{category}] {rule_id}: {desc} (score: {rule_score})"
            )

        # --- Revised Normalization ---
        # Use a higher denominator to reflect conservative scaling
        denominator = max(severity_sum * 30, 1)  # ← adjust this multiplier as needed
        normalized_score = int((total_score / denominator) * 20)
        normalized_score = min(normalized_score, 20)

        logger.info(f"[YARA] Final raw_score={total_score}, severity_sum={severity_sum}, normalized={normalized_score}")
        return normalized_score, reasons