from pathlib import Path
from typing import Dict, Any

def build_error_report(apk_path: Path, error_msg: str = "Unknown error") -> Dict[str, Any]:
    """
    Constructs a standardized error report for an APK.

    Args:
        apk_path (Path): Path to the APK that failed to process.
        error_msg (str): Description of the error.

    Returns:
        Dict[str, Any]: Structured error report.
    """
    return {
        "package": apk_path.stem,
        "apk_metadata": {
            "package_name": apk_path.stem,
            "source_apk": str(apk_path)
        },
        "verdict": "error",
        "score": 0,
        "events": [],
        "yara_matches": [],
        "static_analysis": {},
        "error": error_msg
    }