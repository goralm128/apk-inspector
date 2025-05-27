from typing import Tuple, List, Dict, Any
import logging
from apk_inspector.reports.models import YaraMatch

logger = logging.getLogger("YaraUtils")

def clean_yara_match(match: Any, enable_logging: bool = True) -> Tuple[List[str], Dict[str, Any]]:
    """
    Ensures YARA match fields are consistently structured.

    Args:
        match (Any): YARA match object with `tags` and `meta` attributes.
        enable_logging (bool): Whether to log type mismatches.

    Returns:
        Tuple[List[str], Dict[str, Any]]: Cleaned (tags, meta) tuple
    """
    # Clean tags
    if isinstance(match.tags, list):
        tags = match.tags
    else:
        if enable_logging:
            logger.warning(f"[YARA] Unexpected tag format: {match.tags}")
        tags = [str(match.tags)]

    # Clean meta
    if isinstance(match.meta, dict):
        meta = match.meta
    else:
        if enable_logging:
            logger.warning(f"[YARA] Unexpected meta format: {match.meta}")
        meta = {}

    return tags, meta

def convert_matches(matches: List[YaraMatch]) -> List[Dict[str, Any]]:
    return [m.to_dict() for m in matches]

def serialize_yara_strings(strings) -> List[Tuple[int, str, str]]:
    return [(s[0], s[1], s[2]) for s in strings]

