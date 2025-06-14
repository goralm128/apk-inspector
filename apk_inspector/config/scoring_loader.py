import yaml
from pathlib import Path
from typing import Dict, Tuple, Any
from apk_inspector.utils.logger import get_logger

logger = get_logger()


def validate_section(section_name: str, section: Any) -> Dict[str, int]:
    if not isinstance(section, dict):
        raise ValueError(f"[ScoringLoader] '{section_name}' must be a dict, got {type(section).__name__}")

    normalized = {}
    for key, value in section.items():
        if not isinstance(key, str):
            raise ValueError(f"[ScoringLoader] Invalid key in '{section_name}': {key} (must be str)")
        if not isinstance(value, int):
            raise ValueError(f"[ScoringLoader] Invalid score for key '{key}' in '{section_name}': {value} (must be int)")
        normalized[str(key).strip().lower()] = value

    return normalized


def load_scoring_profile(path: Path) -> Tuple[
    Dict[str, int],  # category_score
    Dict[str, int],  # tag_score
    Dict[str, int],  # severity_score
    Dict[str, int],  # path_type_score
]:
    try:
        with path.open("r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        if not isinstance(config, dict):
            raise ValueError("[ScoringLoader] YAML root must be a dictionary")

        category_score = validate_section("category_score", config.get("category_score", {}))
        tag_score = validate_section("tag_score", config.get("tag_score", {}))
        severity_score = validate_section("severity_score", config.get("severity_score", {}))
        path_type_score = validate_section("path_type_score", config.get("path_type_score", {}))

        logger.info(f"[ScoringLoader] Scoring profile loaded from {path}")
        return category_score, tag_score, severity_score, path_type_score

    except Exception as ex:
        logger.error(f"[ScoringLoader] Failed to load or validate scoring profile: {ex}")
        raise
