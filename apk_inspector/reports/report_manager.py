from typing import List, Dict, Any, Tuple
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

from apk_inspector.reports.models import ApkSummary
from apk_inspector.reports.summary.summary_builder import ApkSummaryBuilder
from apk_inspector.reports.report_saver import ReportSaver
from apk_inspector.utils.yara_utils import ensure_yara_models
from apk_inspector.utils.logger import get_logger

from apk_inspector.visual.chart_utils import (
    generate_stacked_chart,
    generate_risk_breakdown_chart,
    generate_tag_pie_chart
)
from apk_inspector.visual.tag_heatmap import visualize_tag_heatmap
from apk_inspector.visual.per_apk_dashboard import (
    generate_per_apk_dashboard,
    generate_index_page
)


class ReportManager:
    def __init__(self, report_saver: ReportSaver):
        self.report_saver = report_saver
        self.logger = get_logger()
        self.run_dir = report_saver.run_dir

    def store_analysis_results(self, results: List[Tuple[Dict[str, Any], ApkSummary]]) -> None:
        if not results:
            self.logger.warning("[!] No results to store.")
            return

        full_reports = [r[0] for r in results]
        summaries = [r[1] for r in results]

        self._save_combined_json(full_reports)
        self._save_summary_outputs(summaries)

        for report, summary in zip(full_reports, summaries):
            pkg = summary.apk_package or "unknown"
            apk_dir = self.report_saver.get_apk_dir(pkg)
            self._save_per_apk_outputs(report, summary, apk_dir)

        self._generate_heatmap(full_reports)
        generate_index_page(summaries, self.run_dir)

    def _save_combined_json(self, reports: List[Dict[str, Any]]) -> None:
        path = self.run_dir / "combined_report.json"
        for report in reports:
            report["risk_band"] = report.get("classification", {}).get("cvss_risk_band", "unknown")
            analyzed_at = report.get("apk_metadata", {}).get("analyzed_at")
            if isinstance(analyzed_at, datetime):
                report["apk_metadata"]["analyzed_at"] = analyzed_at.isoformat()
        if not self.report_saver._save_json(path, reports, "Combined report"):
            self.logger.error("[✗] Failed saving combined_report.json")

    def _save_summary_outputs(self, summaries: List[ApkSummary]) -> None:
        json_path = self.run_dir / "combined_summary.json"
        csv_path = self.run_dir / "combined_summary.csv"
        self.report_saver._save_json(json_path, [s.to_dict() for s in summaries], "Combined summary JSON")
        try:
            ApkSummaryBuilder.export_csv(summaries, csv_path)
        except Exception as ex:
            self.logger.error(f"[✗] CSV export failed: {ex}")

    def _save_per_apk_outputs(self, report: Dict[str, Any], summary: ApkSummary, apk_dir: Path) -> None:
        pkg = summary.apk_package or "unknown"

        # Save raw report
        self.report_saver.save_report(report)

        # Save categorized YARA JSON
        self._save_yara_json(report, apk_dir, pkg)

        # Save YARA tag pie chart
        self._save_tag_pie(report, apk_dir, pkg)

        # Save stacked charts
        self._save_stacked_charts(report, apk_dir, pkg)

        # Save risk breakdown
        generate_risk_breakdown_chart(summary, apk_dir)

        # Save summary CSV (optional)
        yara_models = ensure_yara_models(report.get("yara_matches", []))
        self.report_saver.save_yara_csv(pkg, yara_models)

        # Generate dashboard HTML
        generate_per_apk_dashboard(summary, apk_dir, apk_dir / "report.json")

    def _save_yara_json(self, report: Dict[str, Any], apk_dir: Path, pkg: str) -> None:
        models = ensure_yara_models(report.get("yara_matches", []))
        grouped = defaultdict(list)
        for m in models:
            grouped[m.meta.get("category", "uncategorized")].append({
                "rule": m.rule,
                "severity": m.meta.get("severity", "medium"),
                "confidence": m.meta.get("confidence", ""),
                "tags": m.tags,
                "file": m.file,
            })
        self.report_saver._save_json(apk_dir / "yara_results.json", grouped, f"YARA results for {pkg}")

    def _save_tag_pie(self, report: Dict[str, Any], apk_dir: Path, pkg: str) -> None:
        tags = Counter(
            tag.lower()
            for match in report.get("yara_matches", [])
            for tag in (match.get("tags", []) if isinstance(match, dict) else getattr(match, "tags", []))
        )
        generate_tag_pie_chart(tags, f"{pkg} — YARA Tags", apk_dir / "yara_tag_pie.png")

    def _save_stacked_charts(self, report: Dict[str, Any], apk_dir: Path, pkg: str) -> None:
        if not report.get("yara_matches"):
            return
        generate_stacked_chart([report], "malware_family", "category",
                               f"{pkg} — Family vs Category", "stacked_family.png", apk_dir)
        generate_stacked_chart([report], "severity", "category",
                               f"{pkg} — Severity vs Category", "stacked_severity.png", apk_dir)

    def _generate_heatmap(self, reports: List[Dict[str, Any]]) -> None:
        all_events = [e for r in reports for e in r.get("events", [])]
        if not all_events:
            self.logger.warning("[~] No dynamic events for heatmap.")
            return
        heatmap_path = self.run_dir / "tag_heatmap.html"
        visualize_tag_heatmap(all_events, str(heatmap_path))
