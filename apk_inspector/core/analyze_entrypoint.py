from apk_inspector.factories.inspector_factory import create_apk_inspector
from apk_inspector.reports.summary_builder import SummaryBuilder
from apk_inspector.reports.report_saver import ReportSaver
from apk_inspector.core.apk_manager import APKManager
from apk_inspector.reports.summary_builder import SummaryBuilder
from apk_inspector.core.apk_manager import APKManager

from pathlib import Path
from typing import Dict, Any


def analyze_apk_entrypoint(
    apk_path: Path,
    hooks_dir: Path,
    report_saver: ReportSaver,
    verbose: bool = True,
    timeout: int = 120
) -> Dict[str, Any]:
    try:
        apk_manager = APKManager()
        package_name = apk_manager.get_package_name(apk_path)
        # Check if package name was successfully retrieved
        if not package_name:
            report_saver.logger.error(f"[{apk_path.name}] Package name could not be determined.")
            return {
                "package": apk_path.stem,
                "verdict": "error",
                "score": 0,
                "events": [],
                "yara_matches": [],
                "static_analysis": {},
                "error": "Package name not found"
            }

        # Setup inspector
        inspector = create_apk_inspector(
            apk_path=apk_path,
            hooks_dir=hooks_dir,
            output_dir=report_saver.output_root, 
            verbose=verbose,
            report_saver=report_saver ,
            timeout=timeout
        )

        report_saver.logger.info(f"[{apk_path.name}] Starting analysis for package: {package_name}")
        full_report = inspector.run()  # Full Dict[str, Any]

        if "error" in full_report:
            return full_report  # It’s already an error structure

        # Save JSON report
        report_saver.logger.info(f"[{apk_path.name}] Report generated successfully.")
        report_saver.save_report(full_report)

        # Save summary
        summary = SummaryBuilder(full_report).build_summary()
        summary_path = report_saver.run_dir / f"{summary['apk_package']}_summary.json"
        report_saver._save_json(summary_path, summary, f"Summary for {summary['apk_package']}")

        return full_report

    except Exception as e:
        report_saver.logger.error(f"[{apk_path.name}] Analysis failed: {e}")
        return _error_result(apk_path, str(e))


def _error_result(apk_path: Path, error_msg: str) -> Dict[str, Any]:
    return {
        "package": apk_path.stem,
        "verdict": "error",
        "score": 0,
        "events": [],
        "yara_matches": [],
        "static_analysis": {},
        "error": error_msg
    }
