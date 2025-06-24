from apk_inspector.factories.inspector_factory import create_apk_inspector
from apk_inspector.reports.summary.summary_builder import ApkSummaryBuilder
from apk_inspector.core.apk_manager import APKManager
from apk_inspector.reports.models import ApkSummary
from apk_inspector.utils.logger import get_logger
from pathlib import Path
from typing import Dict, Any, Tuple
from datetime import datetime


def analyze_apk_and_summarize(
    apk_path: Path,
    hooks_dir: Path,
    run_dir: Path,
    verbose: bool = True,
    timeout: int = 120,
    keep_installed: bool = True
) -> Tuple[Dict[str, Any], ApkSummary]:
    logger = get_logger()
    start_time = datetime.now()
    logger.info(f"[~] Starting analysis for: {apk_path.name}")

    apk_manager = APKManager(logger=logger)

    try:
        package_name = apk_manager.get_package_name(apk_path)
        if not package_name:
            raise ValueError(f"Could not extract package name from {apk_path}")

        if not apk_manager.install_apk(apk_path):
            raise RuntimeError(f"Failed to install {apk_path.name}")

        inspector = create_apk_inspector(
            apk_path=apk_path,
            hooks_dir=hooks_dir,
            run_dir=run_dir,
            verbose=verbose,
            timeout=timeout
        )

        report = inspector.run()

        if "error" in report:
            raise RuntimeError(report.get("error", "Unknown analysis error"))

        summary = ApkSummaryBuilder(report).build_summary()
        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"[✓] Completed analysis for {package_name} in {duration:.2f}s")
        return report, summary

    except Exception as ex:
        logger.exception(f"[✗] Failure analyzing {apk_path.name}")
        return _error_report(apk_path, str(ex)), ApkSummary(error=str(ex))

    finally:
        if not keep_installed:
            try:
                apk_manager.uninstall_package(package_name)
                logger.info(f"[~] Uninstalled {package_name} after analysis.")
            except Exception as ex:
                logger.warning(f"[~] Failed to uninstall package: {ex}")


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
