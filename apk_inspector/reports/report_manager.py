from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
from datetime import datetime
from apk_inspector.reports.models import ApkSummary
from apk_inspector.reports.summary.summary_builder import ApkSummaryBuilder
from apk_inspector.reports.report_saver import ReportSaver
from apk_inspector.utils.yara_utils import ensure_yara_models
from apk_inspector.visual.chart_utils import generate_stacked_chart
from apk_inspector.visual.dashboard_generator import generate_html_dashboard
from apk_inspector.visual.chart_utils import generate_risk_breakdown_charts
from apk_inspector.visual.tag_heatmap import visualize_tag_heatmap

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
        
        flat_events = []
        for report in full_reports:
            flat_events.extend(report.get("events", []))

        if flat_events:
            heatmap_path = self.run_dir / "tag_heatmap.html"
            visualize_tag_heatmap(flat_events, str(heatmap_path))
        else:
            self.logger.warning("[~] No dynamic events found to generate heatmap.")

        # Charts
        self.generate_tag_pie_chart(full_reports)

        generate_stacked_chart(
            reports=full_reports,
            index_field="malware_family",
            column_field="category",
            title="Malware Family by YARA Category",
            filename="stacked_family_chart.png",
            run_dir=self.run_dir
        )

        generate_stacked_chart(
            reports=full_reports,
            index_field="severity",
            column_field="category",
            title="YARA Matches by Severity and Category",
            filename="stacked_severity_chart.png",
            run_dir=self.run_dir
        )

        # Per-APK risk breakdown charts
        risk_charts = generate_risk_breakdown_charts(summaries, self.run_dir)

        # Collect all chart paths
        all_charts = [
            self.run_dir / "yara_tag_pie.png",
            self.run_dir / "stacked_family_chart.png",
            self.run_dir / "stacked_severity_chart.png",
        ] + risk_charts

        # Dashboard HTML
        generate_html_dashboard(
            run_dir=self.run_dir,
            report_json_path=self.run_dir / "combined_report.json",
            summary_csv_path=self.run_dir / "combined_summary.csv",
            charts=all_charts,
            summaries=summaries,
            logger=self.logger
        )

    def _save_combined_json(self, reports: List[Dict[str, Any]]) -> None:
        path = self.run_dir / "combined_report.json"
        enriched = 0

        for report in reports:
            classification = report.get("classification", {})
            if "cvss_risk_band" in classification:
                report["risk_band"] = classification["cvss_risk_band"]
                enriched += 1
            else:
                report["risk_band"] = "unknown"

            metadata = report.get("apk_metadata", {})
            if isinstance(metadata.get("analyzed_at"), datetime):
                metadata["analyzed_at"] = metadata["analyzed_at"].isoformat()

            # Flatten triggered rules
            triggered = report.get("triggered_rule_results", [])
            for rule in triggered:
                if isinstance(rule, dict):
                    rule.setdefault("apk_package", metadata.get("package_name", "unknown"))

        self.logger.info(f"[~] Enriched risk_band in {enriched}/{len(reports)} reports.")
        success = self.report_saver._save_json(path, reports, label="Combined report")
        if not success:
            self.logger.error("[✗] Failed to save combined JSON report")

    def _save_yara_summary(self, reports: List[Dict[str, Any]]) -> None:
        summary: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

        for report in reports:
            package = report.get("apk_metadata", {}).get("package_name", report.get("package", "unknown"))
            raw_matches = report.get("yara_matches", [])
            models = ensure_yara_models(raw_matches)

            category_groups = defaultdict(list)
            for match in models:
                category = match.meta.get("category", "uncategorized")
                entry = {
                    "rule": match.rule,
                    "category": category,
                    "severity": match.meta.get("severity", "medium"),
                    "confidence": match.meta.get("confidence", ""),
                    "tags": match.tags,
                    "file": match.file,
                }
                category_groups[category].append(entry)

            summary[package] = dict(category_groups)

        path = self.run_dir / "yara_results.json"
        success = self.report_saver._save_json(path, summary, label="YARA summary")

        if not success:
            self.logger.error("[✗] Failed to save grouped YARA summary")

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
        except Exception as ex:
            self.logger.error(f"[✗] Failed to save summary CSV: {ex}")

    def generate_tag_pie_chart(self, reports: List[Dict[str, Any]]) -> Optional[Path]:
        tag_counter = Counter()

        for report in reports:
            for match in report.get("yara_matches", []):
                tags = match.get("tags", []) if isinstance(match, dict) else getattr(match, "tags", [])
                tag_counter.update([t.lower() for t in tags])

        if not tag_counter:
            self.logger.warning("[~] No YARA tags found to generate pie chart.")
            return None

        top_tags = tag_counter.most_common(8)
        labels, sizes = zip(*top_tags)

        fig, ax = plt.subplots()
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        ax.set_title("YARA Tag Distribution")
        ax.axis("equal")

        output_path = self.run_dir / "yara_tag_pie.png"
        fig.savefig(output_path, bbox_inches="tight")
        plt.close(fig)

        self.logger.info(f"[✓] Saved YARA tag pie chart to: {output_path.resolve()}")
        return output_path