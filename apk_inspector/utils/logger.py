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
