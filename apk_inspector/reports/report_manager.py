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

        for report, summary in zip(full_reports, summaries):
            package = report.get("apk_metadata", {}).get("package_name", "unknown")
            self._save_per_apk_yara_results(report, package)
            self._save_per_apk_tag_pie(report, package)
            self._save_per_apk_stacked_charts(report, package)

        flat_events = []
        for report in full_reports:
            flat_events.extend(report.get("events", []))

        if flat_events:
            heatmap_path = self.run_dir / "tag_heatmap.html"
            visualize_tag_heatmap(flat_events, str(heatmap_path))
        else:
            self.logger.warning("[~] No dynamic events found to generate heatmap.")

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

        risk_charts = generate_risk_breakdown_charts(summaries, self.run_dir)

        all_charts = [
            self.run_dir / "yara_tag_pie.png",
            self.run_dir / "stacked_family_chart.png",
            self.run_dir / "stacked_severity_chart.png",
        ] + risk_charts

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

        success_json = self.report_saver._save_json(json_path, [s.to_dict() for s in summaries], label="Summary JSON")
        if not success_json:
            self.logger.error("[✗] Failed to save summary JSON")

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

        output_path = self.run_dir / "yara_tag_pie.png"
        return self._generate_tag_pie_chart(tag_counter, "YARA Tag Distribution", output_path)

    def _save_per_apk_yara_results(self, report: Dict[str, Any], package: str) -> None:
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

        out_path = self.run_dir / f"{package}_yara_results.json"
        self.report_saver._save_json(out_path, dict(category_groups), label=f"YARA results for {package}")

    def _save_per_apk_tag_pie(self, report: Dict[str, Any], package: str) -> None:
        tag_counter = Counter()
        for match in report.get("yara_matches", []):
            tags = match.get("tags", []) if isinstance(match, dict) else getattr(match, "tags", [])
            tag_counter.update([t.lower() for t in tags])

        output_path = self.run_dir / f"{package}_yara_tag_pie.png"
        self._generate_tag_pie_chart(tag_counter, f"YARA Tags: {package}", output_path)

    def _save_per_apk_stacked_charts(self, report: Dict[str, Any], package: str) -> None:
        rows = self._extract_yara_chart_rows(report)
        if not rows:
            self.logger.warning(f"[~] No YARA metadata to generate stacked charts for {package}")
            return

        generate_stacked_chart(
            reports=[report],
            index_field="malware_family",
            column_field="category",
            title=f"Malware Family vs Category: {package}",
            filename=f"{package}_stacked_family_chart.png",
            run_dir=self.run_dir
        )

        generate_stacked_chart(
            reports=[report],
            index_field="severity",
            column_field="category",
            title=f"Severity vs Category: {package}",
            filename=f"{package}_stacked_severity_chart.png",
            run_dir=self.run_dir
        )

    def _extract_yara_chart_rows(self, report: Dict[str, Any]) -> List[Dict[str, str]]:
        rows = []
        yara_matches = report.get("yara_matches", [])
        for match in yara_matches:
            meta = match.get("meta", {})
            rows.append({
                "malware_family": str(meta.get("malware_family", "unknown")).lower(),
                "severity": str(meta.get("severity", "unknown")).lower(),
                "category": str(meta.get("category", "uncategorized")).lower()
            })
        return rows

    def _generate_tag_pie_chart(self, tag_counter: Counter, title: str, output_path: Path) -> Optional[Path]:
        if not tag_counter:
            self.logger.warning(f"[~] No tags found for pie chart: {title}")
            return None

        top_tags = tag_counter.most_common(8)
        labels, sizes = zip(*top_tags)

        fig, ax = plt.subplots()
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        ax.set_title(title)
        ax.axis("equal")

        fig.savefig(output_path, bbox_inches="tight")
        plt.close(fig)

        self.logger.info(f"[✓] Saved pie chart: {output_path.resolve()}")
        return output_path
