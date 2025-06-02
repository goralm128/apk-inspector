from typing import List, Dict, Any, Tuple

from apk_inspector.reports.models import ApkSummary
from apk_inspector.reports.summary.summary_builder import ApkSummaryBuilder
from apk_inspector.reports.report_saver import ReportSaver
from apk_inspector.utils.logger import get_logger


class ReportManager:
    """
    Coordinates report saving: full reports, summaries, YARA, etc.
    Uses ReportSaver to persist the files.
    """

    def __init__(self, report_saver: ReportSaver):
        self.report_saver = report_saver
        self.logger = get_logger()
        self.run_dir = report_saver.run_dir

    def store_analysis_results(self, results: List[Tuple[Dict[str, Any], ApkSummary]]) -> None:
        if not results:
            self.logger.warning("[!] No analysis results to store.")
            return

        full_reports = [r[0] for r in results]
        summaries = [r[1] for r in results]

        self._save_combined_json(full_reports)
        self._save_yara_summary(full_reports)
        self._save_summary_outputs(summaries)

    def _save_combined_json(self, reports: List[Dict[str, Any]]) -> None:
        path = self.run_dir / "combined_report.json"
        success = self.report_saver._save_json(path, reports, label="Combined report")
        if not success:
            self.logger.error("[✗] Failed to save combined JSON report")

    def _save_yara_summary(self, reports: List[Dict[str, Any]]) -> None:
        yara_summary = {
            r.get("apk_metadata", {}).get("package_name", r.get("package", "unknown")):
            [m.get("rule") if isinstance(m, dict) else getattr(m, "rule", "") for m in r.get("yara_matches", [])]
            for r in reports
        }
        path = self.run_dir / "yara_results.json"
        success = self.report_saver._save_json(path, yara_summary, label="YARA summary")
        if not success:
            self.logger.error("[✗] Failed to save YARA summary")

    def _save_summary_outputs(self, summaries: List[ApkSummary]) -> None:
        json_path = self.run_dir / "combined_summary.json"
        csv_path = self.run_dir / "combined_summary.csv"

        # Save JSON
        success_json = self.report_saver._save_json(json_path, [s.to_dict() for s in summaries], label="Summary JSON")
        if not success_json:
            self.logger.error("[✗] Failed to save summary JSON")

        # Save CSV
        try:
            ApkSummaryBuilder.export_csv(summaries, csv_path)
            self.logger.info(f"[✓] CSV summary saved to: {csv_path.resolve()}")
        except Exception as e:
            self.logger.error(f"[✗] Failed to save summary CSV: {e}")
