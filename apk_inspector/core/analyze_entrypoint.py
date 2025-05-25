from apk_inspector.factories.inspector_factory import create_apk_inspector
from apk_inspector.reports.summary_builder import SummaryBuilder
from apk_inspector.reports.report_saver import ReportSaver
from apk_inspector.core.apk_manager import APKManager

from pathlib import Path
from typing import Dict, Any


def analyze_apk_entrypoint(
    apk_path: Path,
    hooks_dir: Path,
    report_saver: ReportSaver,  # NEW
    verbose: bool = True
) -> Dict[str, Any]:
    try:
        apk_manager = APKManager()
        package_name = apk_manager.get_package_name(apk_path)
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
            output_dir=report_saver.output_root,  # keep for consistency
            verbose=verbose,
            report_saver=report_saver  # pass in
        )
        report = inspector.run()
        if not report:
            report_saver.logger.error(f"[{apk_path.name}] No report generated.")
            return {
                "package": apk_path.stem,
                "verdict": "error",
                "score": 0,
                "events": [],
                "yara_matches": [],
                "static_analysis": {},
                "error": "No report generated"
            }

        # Save full report
        report_saver.logger.info(f"[{apk_path.name}] Report generated successfully.")
        report_saver.save_report(report)

        # Save summary
        summary = SummaryBuilder(report).build_summary()
        summary_path = report_saver.run_dir / f"{summary['apk_package']}_summary.json"
        report_saver._save_json(summary_path, summary, f"Summary for {summary['apk_package']}")

        return report

    except Exception as e:
        report_saver.logger.error(f"[{apk_path.name}] Analysis failed: {e}")
        # Return a structured error response
        return {
            "package": apk_path.stem,
            "verdict": "error",
            "score": 0,
            "events": [],
            "yara_matches": [],
            "static_analysis": {},
            "error": str(e)
        }
