from typing import Tuple, List, Dict, Any
from apk_inspector.reports.schemas import YaraMatchModel
from pydantic import ValidationError
from apk_inspector.utils.logger import get_logger

logger = get_logger()


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
            except Exception as e:
                meta[k] = repr(v)
                if enable_logging:
                    logger.warning(f"[YARA:{rule_name}] Failed to clean meta[{k}]: {e}")
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
        except Exception as e:
            logger.warning(f"[YARA] Failed to serialize YARA string: {e}")
    return serialized


def convert_matches(matches: List[Any]) -> List[Dict[str, Any]]:
    """
    Converts raw YARA hits to a list of validated YaraMatchModel dicts.
    Skips and logs invalid entries.
    """
    result: List[Dict[str, Any]] = []

    for index, raw in enumerate(matches):
        try:
            if isinstance(raw, YaraMatchModel):
                match = raw
            elif isinstance(raw, dict):
                match = YaraMatchModel(**raw)
            elif hasattr(raw, "to_dict"):
                match = YaraMatchModel(**raw.to_dict())
            else:
                logger.warning(f"[YARA] Unsupported match type at index {index}: {type(raw)}")
                continue

            result.append(match.model_dump())

        except ValidationError as ve:
            logger.error(f"[YARA] Match validation failed at index {index}: {ve}")
        except Exception as e:
            logger.exception(f"[YARA] Unexpected error at index {index}: {e}")

    return result


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

        logger.debug(f"[YARA] Scoring dictionary types: "
                     f"category_score={type(category_score)}, "
                     f"tag_score={type(tag_score)}, "
                     f"severity_score={type(severity_score)}")
        logger.debug(f"[YARA] Known tag_score keys: {sorted(tag_score.keys())}")
        logger.debug(f"[YARA] Received {len(yara_hits)} raw YARA hits")

        # --- Validate Hits ---
        for index, hit in enumerate(yara_hits):
            try:
                logger.debug(f"[YARA] Validating hit #{index}: {type(hit)}")
                if isinstance(hit, YaraMatchModel):
                    validated_hits.append(hit)
                elif isinstance(hit, dict):
                    validated_hits.append(YaraMatchModel.model_validate(hit))
                else:
                    logger.warning(f"[YARA] Unsupported hit type at index {index}: {type(hit)}")
            except ValidationError as ve:
                reasons.append(f"[ERROR] Invalid YARA match #{index}: {ve}")
                logger.error(f"[YARA] Validation failed at index {index}: {ve}")
            except Exception as e:
                reasons.append(f"[ERROR] Unexpected error in hit #{index}: {e}")
                logger.exception(f"[YARA] Unexpected error parsing hit #{index}: {e}")

        logger.debug(f"[YARA] Successfully validated {len(validated_hits)} YARA hits")

        # --- Score Each Validated Hit ---
        for index, hit in enumerate(validated_hits):
            try:
                rule_id = hit.rule
                tags = hit.tags
                
                normalized_tag_score = {k.lower(): v for k, v in tag_score.items()}
                normalized_tags = [t.lower().strip() for t in tags]

                meta = hit.meta or {}

                desc = str(meta.get("description", rule_id))
                category = str(meta.get("category", "uncategorized")).lower()
                severity = str(meta.get("severity", "medium")).lower()
                confidence = str(meta.get("confidence", "50"))
                impact = meta.get("impact")
                family = meta.get("malware_family")

                logger.debug(f"[YARA:{rule_id}] Evaluating hit #{index}")
                logger.debug(f"[YARA:{rule_id}] Tags: {tags}")
                logger.debug(f"[YARA:{rule_id}] Meta: category={category}, severity={severity}, confidence={confidence}")

                rule_score = 0
                reason_parts = []

                # --- Scoring ---
                category_pts = category_score.get(category, 0)
                severity_pts = severity_score.get(severity, 10)
            
                tag_pts = sum(normalized_tag_score.get(tag, 0) for tag in normalized_tags)

                rule_score += category_pts + severity_pts + tag_pts

                logger.debug(f"[YARA:{rule_id}] Score breakdown: category={category_pts}, severity={severity_pts}, tags_total={tag_pts}")

                # --- Confidence Bonus ---
                try:
                    if int(confidence) >= 90:
                        rule_score += 5
                        reason_parts.append("confidence high (90+)")
                        logger.debug(f"[YARA:{rule_id}] High confidence bonus applied")
                except ValueError:
                    logger.warning(f"[YARA:{rule_id}] Invalid confidence format: {confidence}")
                    reasons.append(f"[WARN] Invalid confidence: {confidence} in rule {rule_id}")

                # --- Optional metadata context ---
                if impact:
                    reason_parts.append(f"impact: {impact}")
                if family:
                    reason_parts.append(f"family: {family}")

                # --- Unmatched Tags ---       
                unmatched_tags = [tag for tag in normalized_tags if tag not in normalized_tag_score]
                if unmatched_tags:
                    logger.debug(f"[YARA:{rule_id}] Unscored tags: {unmatched_tags}")
                    reasons.append(f"[INFO] Unscored tags in {rule_id}: {', '.join(unmatched_tags)}")

                # --- Compose Reason ---
                reason_summary = (
                    f"[YARA][{severity.upper()}][{category}] {rule_id}: {desc} "
                    f"(score: {rule_score})"
                )
                if reason_parts:
                    reason_summary += f" [{' | '.join(reason_parts)}]"

                reasons.append(reason_summary)
                total_score += rule_score

                logger.debug(f"[YARA:{rule_id}] Final rule score: {rule_score}")

            except Exception as e:
                logger.exception(f"[YARA] Failed processing validated hit #{index}: {e}")
                reasons.append(f"[ERROR] Failed to evaluate YARA hit #{index}: {e}")

        logger.info(f"[YARA] Evaluation complete: total_score={total_score}, hits={len(validated_hits)}")
        return total_score, reasons
