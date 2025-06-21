from typing import List, Dict
from pathlib import Path
from collections import defaultdict, Counter

from apk_inspector.reports.models import ApkSummary
from apk_inspector.utils.yara_utils import ensure_yara_models
from apk_inspector.visual.chart_utils import (
    generate_stacked_chart, generate_risk_breakdown_chart, generate_tag_pie_chart
)
from apk_inspector.visual.tag_heatmap import visualize_tag_heatmap
from apk_inspector.visual.per_apk_dashboard import generate_per_apk_dashboard

from apk_inspector.utils.logger import get_logger


class VisualizationGenerator:
    def __init__(self, report_saver, run_dir: Path):
        self.logger = get_logger()
        self.report_saver = report_saver
        self.run_dir = run_dir

    def save_per_apk_visuals(self, report: Dict, summary: ApkSummary, apk_dir: Path) -> None:
        pkg = summary.apk_package or "unknown"
        self._save_yara_json(report, apk_dir, pkg)
        self._save_tag_pie(report, apk_dir, pkg)
        self._save_stacked_charts(report, apk_dir, pkg)
        generate_risk_breakdown_chart(summary, apk_dir)

        yara_models = ensure_yara_models(report.get("yara_matches", []))
        self.report_saver.save_yara_csv(pkg, yara_models)
        generate_per_apk_dashboard(summary, apk_dir, apk_dir / "report.json")

    def _save_yara_json(self, report: Dict, apk_dir: Path, pkg: str):
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

    def _save_tag_pie(self, report: Dict, apk_dir: Path, pkg: str):
        tags = Counter(
            tag.lower()
            for match in report.get("yara_matches", [])
            for tag in (match.get("tags", []) if isinstance(match, dict) else getattr(match, "tags", []))
        )
        generate_tag_pie_chart(tags, f"{pkg} — YARA Tags", apk_dir / "yara_tag_pie.png")

    def _save_stacked_charts(self, report: Dict, apk_dir: Path, pkg: str):
        if not report.get("yara_matches"):
            return
        generate_stacked_chart([report], "malware_family", "category",
                               f"{pkg} — Family vs Category", "stacked_family.png", apk_dir)
        generate_stacked_chart([report], "severity", "category",
                               f"{pkg} — Severity vs Category", "stacked_severity.png", apk_dir)

    def generate_heatmap(self, reports: List[Dict]) -> None:
        all_events = [e for r in reports for e in r.get("events", [])]
        if not all_events:
            self.logger.warning("[~] No dynamic events for heatmap.")
            return
        heatmap_path = self.run_dir / "tag_heatmap.html"
        visualize_tag_heatmap(all_events, str(heatmap_path))
