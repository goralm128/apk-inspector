import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

# Centralized logger name
LOGGER_NAME = "apk_inspector"

def init_logging(
    verbose: bool = False,
    log_path: Optional[Path] = None,
    log_to_console: bool = True,
    log_to_file: bool = True
) -> logging.Logger:
    """
    Initializes and configures the main project logger.

    Args:
        verbose (bool): Enable DEBUG logging.
        log_path (Optional[Path]): Optional log file path.
        log_to_console (bool): Enable logging to stdout.
        log_to_file (bool): Enable logging to file.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Avoid duplicate logs in dev or test environments
    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = _create_formatter()

    if log_to_file and log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    if log_to_console:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    return logger


def _create_formatter() -> logging.Formatter:
    """
    Create a default log formatter.

    Returns:
        logging.Formatter
    """
    return logging.Formatter("[%(levelname)s] %(asctime)s - %(message)s")


def get_logger() -> logging.Logger:
    """
    Retrieve the main project logger.

    Returns:
        logging.Logger
    """
    return logging.getLogger(LOGGER_NAME)


def log_verdict_debug(
    logger: logging.Logger,
    package_name: str,
    score: int,
    verdict_label: str,
    reasons: List[str],
    events: Optional[List[Dict[str, Any]]] = None,
    yara_hits: Optional[List[Dict[str, Any]]] = None,
    static_info: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log detailed debugging information for analysis verdicts.

    Args:
        logger (logging.Logger): The logger instance to use.
        package_name (str): APK package name.
        score (int): Numeric score.
        verdict_label (str): Human-readable verdict label.
        reasons (List[str]): List of verdict reasons.
        events (Optional[List]): Captured dynamic events.
        yara_hits (Optional[List]): YARA match results.
        static_info (Optional[Dict]): Static analysis metadata.
    """
    logger.info(f"[{package_name}] Score: {score} | Verdict: {verdict_label}")
    
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
