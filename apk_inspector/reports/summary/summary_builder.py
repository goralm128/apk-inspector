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
        self.meta = full_report.get("apk_metadata", {})
        self.classification = full_report.get("classification") or full_report.get("report_summary", {}).get("classification", {})
        self.breakdown = full_report.get("risk_breakdown") or full_report.get("report_summary", {}).get("risk_breakdown", {})
        self.events = full_report.get("dynamic_analysis", {}).get("original_events", [])
        self.hook_counts = full_report.get("hook_event_counts", {})
        self.hook_coverage = full_report.get("hook_coverage_percent", 0.0)
        self.yara_matches = full_report.get("yara_matches", [])
        self.summary = full_report.get("dynamic_analysis", {}).get("summary", DEFAULT_DYNAMIC_SUMMARY.copy())

    def build_summary(self) -> ApkSummary:
        score = self.classification.get("score", 0)
        label = self.classification.get("verdict") or self.classification.get("label", "unknown")
        flags = self.classification.get("flags", [])

        analyzer = JustificationAnalyzer([e.get("justification", {}) for e in self.events if isinstance(e, dict)])
        cvss_scores = self._collect_cvss_scores()

        return ApkSummary(
            apk_name=self.meta.get("apk_name", self.meta.get("package_name")),
            apk_package=self.meta.get("package_name"),
            sha256=self.meta.get("hash", {}).get("sha256", "N/A"),
            classification=label,
            risk_score=score,
            cvss_risk_band=compute_cvss_band(cvss_scores),
            key_flags=flags,
            top_tags=analyzer.top_tags(),
            top_sources=analyzer.top_sources(),
            top_triggered_rules=self._top_rule_ids(),
            risk_breakdown=self.breakdown,
            scoring_justification=self.report.get("scoring_justification", {}),
            dynamic_summary=self.summary,
            hook_coverage_percent=self.hook_coverage,
            hook_event_counts=self.hook_counts,
            behavioral_categories=[k for k, v in self.summary.items() if v > 0],
            yara_matches=self._yara_rule_names(),
            yara_match_count=len(self.yara_matches),
            error=""
        )

    def _collect_cvss_scores(self) -> List[float]:
        return [
            detail.get("cvss", 0.0)
            for event in self.events
            for detail in event.get("metadata", {}).get("triggered_rule_details", [])
            if isinstance(detail, dict)
        ]

    def _top_rule_ids(self) -> List[str]:
        rule_ids = [
            r.get("rule_id")
            for r in self.report.get("triggered_rule_results", [])
            if isinstance(r, dict)
        ]
        return [rid for rid, _ in Counter(rule_ids).most_common(5)]

    def _yara_rule_names(self) -> List[str]:
        return [m["rule"] if isinstance(m, dict) else getattr(m, "rule", "unknown") for m in self.yara_matches]

    @staticmethod
    def build_combined_summaries(reports: List[Dict[str, Any]]) -> List[ApkSummary]:
        return [ApkSummaryBuilder(r).build_summary() for r in reports]

    @staticmethod
    def export_csv(summary_list: List[ApkSummary], output_path: Path) -> Path:
        exporter = CsvSummaryExporter(output_path)
        return exporter.write(summary_list)
