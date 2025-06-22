from collections import Counter
from apk_inspector.reports.models import ApkSummary
from apk_inspector.analysis.justification_analyzer import JustificationAnalyzer
from apk_inspector.config.defaults import DEFAULT_DYNAMIC_SUMMARY
from apk_inspector.reports.summary.csv_summary_exporter import CsvSummaryExporter
from apk_inspector.utils.scoring_utils import compute_cvss_band
from apk_inspector.utils.logger import get_logger
from typing import List, Dict, Any
from pathlib import Path

class ApkSummaryBuilder:
    def __init__(self, full_report: Dict[str, Any], logger=None):
        self.report = full_report
        self.logger = logger or get_logger()

    def build_summary(self) -> ApkSummary:
        meta = self.report.get("apk_metadata", {})
        verdict = self.report.get("classification") or self.report.get("report_summary", {}).get("classification", {})
        score = verdict.get("score") or self.report.get("score") or 0
        label = verdict.get("verdict") or verdict.get("label") or "unknown"
        flags = verdict.get("flags") or []
        breakdown = self.report.get("risk_breakdown") or self.report.get("report_summary", {}).get("risk_breakdown", {})

        # --- Events ---
        events = self.report.get("dynamic_analysis", {}).get("original_events", [])
        justifications = [e.get("justification", {}) for e in events if isinstance(e, dict)]
        analyzer = JustificationAnalyzer(justifications)
        top_tags = analyzer.top_tags()
        top_sources = analyzer.top_sources()
        sources = [e.get("source", "unknown") for e in events if isinstance(e, dict)]
        rule_ids = [
            r.get("rule_id") for r in self.report.get("triggered_rule_results", [])
            if isinstance(r, dict)
        ]

        top_triggered_rules = [rid for rid, _ in Counter(rule_ids).most_common(5)]

        # --- Dynamic Summary ---
        summary = self.report.get("dynamic_analysis", {}).get("summary", DEFAULT_DYNAMIC_SUMMARY.copy())
        behavioral_categories = [k for k, v in summary.items() if v > 0]

        # --- Hook Info ---
        hook_counts = self.report.get("hook_event_counts", {})
        hook_coverage = self.report.get("hook_coverage_percent", 0.0)

        # --- CVSS ---
        cvss_scores = [
            rd.get("cvss", 0.0)
            for e in events
            for rd in e.get("metadata", {}).get("triggered_rule_details", [])
            if isinstance(rd, dict)
        ]
        max_cvss = max(cvss_scores, default=0.0)
        cvss_band = compute_cvss_band(max_cvss)

        return ApkSummary(
            apk_name=meta.get("apk_name", meta.get("package_name")),
            apk_package=meta.get("package_name"),
            sha256=meta.get("hash", {}).get("sha256", "N/A"),
            classification=label,
            risk_score=score,
            cvss_risk_band=cvss_band,
            key_flags=flags,
            top_tags=top_tags,
            top_sources=top_sources,
            top_triggered_rules=top_triggered_rules,
            risk_breakdown=breakdown,
            scoring_justification=self.report.get("scoring_justification", {}),
            dynamic_summary=summary,
            hook_coverage_percent=hook_coverage,
            hook_event_counts=hook_counts,
            behavioral_categories=behavioral_categories,
            yara_matches=[
                m["rule"] if isinstance(m, dict) else getattr(m, "rule", "unknown")
                for m in self.report.get("yara_matches", [])
            ],
            yara_match_count=len(self.report.get("yara_matches", [])),
            error=""
        )

    @staticmethod
    def build_combined_summaries(reports: List[Dict[str, Any]]) -> List[ApkSummary]:
        return [ApkSummaryBuilder(r).build_summary() for r in reports]

    @staticmethod
    def export_csv(summary_list: List[ApkSummary], output_path: Path) -> Path:
        exporter = CsvSummaryExporter(output_path)
        return exporter.write(summary_list)
