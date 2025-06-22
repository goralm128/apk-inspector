from typing import List, Dict, Any
from pathlib import Path
from collections import Counter
from apk_inspector.reports.models import ApkSummary
from apk_inspector.analysis.justification_analyzer import JustificationAnalyzer
from apk_inspector.config.defaults import DEFAULT_DYNAMIC_SUMMARY
from apk_inspector.reports.summary.csv_summary_exporter import CsvSummaryExporter
from apk_inspector.utils.scoring_utils import compute_cvss_band
from apk_inspector.utils.logger import get_logger

class ApkSummaryBuilder:
    def __init__(self, full_report: Dict[str, Any], logger=None):
        self.report = full_report
        self.logger = logger or get_logger()

    def build_summary(self) -> ApkSummary:
        meta = self.report.get("apk_metadata", {})
        # Use correct location for classification info
        verdict = self.report.get("classification") or self.report.get("report_summary", {}).get("classification", {})
        # fallback to top-level keys if report is minimal
        score = verdict.get("score") or self.report.get("score") or 0
        label = verdict.get("verdict") or verdict.get("label") or "unknown"
        flags = verdict.get("flags") or []

        # Fix breakdown source
        breakdown = self.report.get("risk_breakdown") or self.report.get("report_summary", {}).get("risk_breakdown", {})

        # cvss detection remains
        cvss_scores = [
            rd.get("cvss", 0.0)
            for e in self.report.get("dynamic_analysis", {}).get("events", [])
            for rd in e.get("metadata", {}).get("triggered_rule_details", [])
            if isinstance(rd, dict)
        ]
        max_cvss = max(cvss_scores, default=0.0)
        cvss_band = compute_cvss_band(max_cvss)

        # Build summary
        return ApkSummary(
            apk_name=meta.get("apk_name", meta.get("package_name")),
            apk_package=meta.get("package_name"),
            sha256=self.report.get("apk_metadata", {}).get("sha256", "N/A"),
            classification=label,
            risk_score=score,
            key_flags=flags,
            dynamic_summary=self.report.get("dynamic_analysis", {}).get("summary", DEFAULT_DYNAMIC_SUMMARY.copy()),
            top_tags=JustificationAnalyzer(
                       [e.get("justification") for e in self.report.get("dynamic_analysis", {}).get("events", []) if e.get("justification")]
                     ).top_tags(),
            top_sources=[],  # add analyzer if needed
            top_triggered_rules=[],
            cvss_risk_band=cvss_band,
            risk_breakdown=breakdown,
            yara_matches=[m["rule"] if isinstance(m, dict) else getattr(m, "rule", "unknown")
                          for m in self.report.get("yara_matches", [])],
            yara_match_count=len(self.report.get("yara_matches", [])),
            error=""
        )

    @staticmethod
    def build_combined_summaries(reports: List[Dict[str, Any]]) -> List[ApkSummary]:
        summaries = []
        for r in reports:
            builder = ApkSummaryBuilder(r)
            summaries.append(builder.build_summary())
        return summaries

    @staticmethod
    def export_csv(summary_list: List[ApkSummary], output_path: Path) -> Path:
        exporter = CsvSummaryExporter(output_path)
        return exporter.write(summary_list)