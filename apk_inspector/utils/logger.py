import logging
from pathlib import Path

def setup_logger(verbose: bool = False, log_path: Path = Path("output/apk_inspector.log")) -> logging.Logger:
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = "[%(levelname)s] %(asctime)s - %(message)s"

    logger = logging.getLogger("APKInspector")
    logger.setLevel(log_level)

    # Prevent duplicate handlers
    if not logger.handlers:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(log_format))
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(logging.Formatter(log_format))

        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

    return logger

from typing import List, Dict, Any, Optional

def log_verdict_debug(
    logger,
    package_name: str,
    score: int,
    verdict_label: str,
    reasons: List[str],
    events: Optional[List[Dict[str, Any]]] = None,
    yara_hits: Optional[List[Dict[str, Any]]] = None,
    static_info: Optional[Dict[str, Any]] = None
):
    logger.info(f"[{package_name}] 🔍 Score: {score} | Verdict: {verdict_label}")
    
    if not reasons:
        logger.warning(f"[{package_name}] No reasons were logged — possible issue in rule logic.")
    else:
        for reason in reasons:
            logger.info(f"[{package_name}] Reason: {reason}")

    if events is not None:
        logger.debug(f"[{package_name}] Event count: {len(events)}")

    if yara_hits is not None:
        logger.debug(f"[{package_name}] YARA matches: {len(yara_hits)}")

    if static_info is not None:
        manifest = static_info.get("manifest_analysis", {})
        logger.debug(f"[{package_name}] Manifest permissions: {manifest.get('usesPermissions', [])}")
        logger.debug(f"[{package_name}] Reflection: {static_info.get('reflection_usage', False)} | Obfuscation: {static_info.get('obfuscation_detected', False)}")

