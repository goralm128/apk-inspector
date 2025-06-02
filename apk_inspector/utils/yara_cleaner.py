from typing import Tuple, List, Dict, Any
from apk_inspector.utils.logger import get_logger

logger = get_logger()

def clean_yara_match(match: Any, enable_logging: bool = True) -> Tuple[List[str], Dict[str, Any]]:
    """
    Normalize YARA match tags and meta for consistent processing.
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
    meta = {}
    if isinstance(raw_meta, dict):
        for k, v in raw_meta.items():
            try:
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

    return tags, meta

