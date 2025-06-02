from apk_inspector.factories.inspector_factory import create_apk_inspector
from apk_inspector.reports.summary.summary_builder import ApkSummaryBuilder
from apk_inspector.core.apk_manager import APKManager
from apk_inspector.reports.models import ApkSummary
from apk_inspector.utils.logger import get_logger

from pathlib import Path
from typing import Dict, Any, Tuple


def analyze_apk_and_summarize(
    apk_path: Path,
    hooks_dir: Path,
    run_dir: Path,
    verbose: bool = True,
    timeout: int = 120,
    keep_installed: bool = True
) -> Tuple[Dict[str, Any], ApkSummary]:
    """
    Analyzes a single APK and produces both the full report and a summarized verdict.

    Returns:
        Tuple[Dict[str, Any], ApkSummary]: Full JSON-style report and simplified summary.
    """
    logger = get_logger()

    try:
        apk_manager = APKManager(logger=logger)
        package_name = apk_manager.get_package_name(apk_path)
        
        if not package_name:
            msg = f"Could not extract package name from {apk_path}"
            logger.error(f"[✗] {msg}")
            return _error_report(apk_path, msg), ApkSummary.from_dict({"error": msg})
 
        installed = apk_manager.install_apk(apk_path)

        if not installed:
            msg = f"Failed to install {apk_path.name}"
            logger.error(f"[✗] {msg}")
            return _error_report(apk_path, msg), ApkSummary.from_dict({"error": msg})
        
        try:

            inspector = create_apk_inspector(
                apk_path=apk_path,
                hooks_dir=hooks_dir,
                run_dir=run_dir,
                verbose=verbose,
                timeout=timeout
            )

            report = inspector.run()
            
        finally:
             if installed and not keep_installed:
                apk_manager.uninstall_package(package_name)

        # If inspector encountered a fatal error, it embeds an "error" key.
        if "error" in report:
            logger.warning(f"[{package_name}] Analysis returned error: {report['error']}")
            return report, ApkSummary.from_dict({"error": report.get("error", "Unknown analysis error")})

        # Build summary from valid report
        summary = ApkSummaryBuilder(report).build_summary()
        return report, summary

    except Exception as e:
        logger.exception(f"[✗] Unexpected failure analyzing {apk_path.name}")
        return _error_report(apk_path, str(e)), ApkSummary.from_dict({"error": str(e)})


def _error_report(apk_path: Path, error_msg: str = "Unknown error") -> Dict[str, Any]:
    return {
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