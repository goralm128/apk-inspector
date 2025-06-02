from typing import List, Dict, Any
from pathlib import Path
from collections import Counter
from apk_inspector.reports.models import ApkSummary
from apk_inspector.analysis.justification_analyzer import JustificationAnalyzer
from apk_inspector.config.defaults import DEFAULT_DYNAMIC_SUMMARY
from apk_inspector.reports.summary.csv_summary_exporter import CsvSummaryExporter
from apk_inspector.utils.logger import get_logger

class ApkSummaryBuilder:
    def __init__(self, full_report: Dict[str, Any], logger=None):
        self.report = full_report
        self.logger = logger or get_logger()

    def build_summary(self) -> ApkSummary:
        meta = self.report.get("apk_metadata", {})
        classification = self.report.get("classification", {})
        dynamic = self.report.get("dynamic_analysis", {})
        yara_matches = self.report.get("yara_matches", [])

        try:
            justifications = [
                e.get("justification")
                for e in dynamic.get("events", [])
                if e.get("justification")
            ]

            analyzer = JustificationAnalyzer(justifications)
            
            # --- YARA match count ---
            yara_match_count = len(yara_matches)

            # --- Top triggered rule IDs ---
            triggered_rules = [
                rid
                for e in dynamic.get("events", [])
                for rid in e.get("metadata", {}).get("triggered_rules", [])
            ]
            top_triggered = [rule for rule, _ in Counter(triggered_rules).most_common(5)]

            # --- CVSS band from triggered rules (optional enhancement) ---
            # If your event metadata includes CVSS scores, extract them
            cvss_scores = [
                rule.get("cvss", 0.0)
                for e in dynamic.get("events", [])
                for rule in e.get("metadata", {}).get("triggered_rule_details", [])
                if isinstance(rule, dict)
            ]
            max_cvss = max(cvss_scores, default=0.0)

            def map_cvss_band(cvss):
                if cvss >= 9.0: return "Critical"
                elif cvss >= 7.0: return "High"
                elif cvss >= 4.0: return "Medium"
                elif cvss > 0.0: return "Low"
                return "Unknown"

            cvss_band = map_cvss_band(max_cvss)

            return ApkSummary(
                apk_name=meta.get("apk_name", meta.get("package_name", "unknown.apk")),
                apk_package=meta.get("package_name", "unknown.package"),
                sha256=meta.get("hash", {}).get("sha256", "N/A"),
                classification=classification.get("verdict", "unknown"),
                risk_score=classification.get("score", 0),
                key_flags=classification.get("flags", []),
                dynamic_summary=dynamic.get("summary", DEFAULT_DYNAMIC_SUMMARY.copy()),
                top_tags=analyzer.top_tags(),
                top_sources=analyzer.top_sources(),
                yara_matches=[
                    m["rule"] if isinstance(m, dict) else getattr(m, "rule", "unknown")
                    for m in yara_matches
                ],
                yara_match_count=yara_match_count,
                top_triggered_rules=top_triggered,
                cvss_risk_band=cvss_band,
                error=""
            )
            
        except Exception as e:
            self.logger.exception(f"[✗] Failed to build summary for {meta.get('package_name', 'unknown')}")
            return ApkSummary(
                apk_name=meta.get("apk_name", "unknown.apk"),
                apk_package=meta.get("package_name", "unknown.package"),
                sha256=meta.get("hash", {}).get("sha256", "N/A"),
                classification="error",
                risk_score=0,
                error=f"Summary build failed: {str(e)}"
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