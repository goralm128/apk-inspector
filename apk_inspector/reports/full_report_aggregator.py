from typing import List, Dict
from pathlib import Path
from datetime import datetime
from dataclasses import asdict

from apk_inspector.reports.models import ApkSummary
from apk_inspector.reports.summary.summary_builder import ApkSummaryBuilder
from apk_inspector.reports.report_saver import ReportSaver
from apk_inspector.utils.logger import get_logger


class FullReportAggregator:
    def __init__(self, report_saver: ReportSaver):
        self.report_saver = report_saver
        self.logger = get_logger()
        self.run_dir = report_saver.run_dir

    def save_combined_json(self, reports: List[Dict]) -> None:
        path = self.run_dir / "combined_report.json"
        for report in reports:
            report["risk_band"] = report.get("classification", {}).get("cvss_risk_band", "unknown")
            if "apk_metadata" in report:
                analyzed_at = report["apk_metadata"].get("analyzed_at")
                if isinstance(analyzed_at, datetime):
                    report["apk_metadata"]["analyzed_at"] = analyzed_at.isoformat()
        metadata_wrapper = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "apk_count": len(reports),
            "reports": reports
        }
        if not self.report_saver._save_json(path, metadata_wrapper, "Combined report"):
            self.logger.error("[✗] Failed to save combined_report.json")

    def save_summary_outputs(self, summaries: List[ApkSummary]) -> None:
        json_path = self.run_dir / "combined_summary.json"
        csv_path = self.run_dir / "combined_summary.csv"
        self.report_saver._save_json(json_path, [s.to_dict() for s in summaries], "Combined summary JSON")
        try:
            ApkSummaryBuilder.export_csv(summaries, csv_path)
        except Exception as ex:
            self.logger.error(f"[✗] CSV export failed: {ex}")
