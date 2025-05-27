import csv
from pathlib import Path
from typing import List, Dict, Any

class SummaryBuilder:
    def __init__(self, full_report: Dict[str, Any]):
        self.report = full_report

    def build_summary(self) -> Dict[str, Any]:
        meta = self.report.get("apk_metadata", {})
        classification = self.report.get("classification", {})
        dynamic = self.report.get("dynamic_analysis", {})
        yara_matches = self.report.get("yara_matches", [])

        return {
            "apk_name": meta.get("apk_name", meta.get("package_name", "unknown.apk")),
            "apk_package": meta.get("package_name", "unknown.package"),
            "sha256": meta.get("hash", {}).get("sha256", "N/A"),
            "classification": classification.get("verdict", "unknown"),
            "risk_score": classification.get("score", 0),
            "key_flags": classification.get("flags", []),
            "dynamic_summary": dynamic.get("summary", {
                "total_events": 0,
                "high_risk_events": 0,
                "network_connections": 0,
                "file_operations": 0,
                "crypto_operations": 0,
                "reflection_usage": 0,
                "native_code_usage": 0,
                "accessibility_service_usage": 0
            }),
            "yara_matches": [m.get("rule", "unknown") for m in yara_matches]
        }

    @staticmethod
    def build_combined_summaries(reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [SummaryBuilder(report).build_summary() for report in reports]

    @staticmethod
    def export_csv(summary_list: List[Dict[str, Any]], output_path: Path) -> Path:
        if not summary_list:
            raise ValueError("No summary data to export.")

        fieldnames = [
            "apk_name",
            "apk_package",
            "sha256",
            "classification",
            "risk_score",
            "high_risk_events",
            "network_connections",
            "file_operations",
            "crypto_operations",
            "reflection_usage",
            "native_code_usage",
            "accessibility_service_usage",
            "yara_matches",
            "key_flags"
        ]

        flat_rows = []
        for s in summary_list:
            dynamic_summary = s.get("dynamic_summary", {})
            flat_rows.append({
                "apk_name": s.get("apk_name"),
                "apk_package": s.get("apk_package"),
                "sha256": s.get("sha256"),
                "classification": s.get("classification"),
                "risk_score": s.get("risk_score"),
                "high_risk_events": dynamic_summary.get("high_risk_events", 0),
                "network_connections": dynamic_summary.get("network_connections", 0),
                "file_operations": dynamic_summary.get("file_operations", 0),
                "crypto_operations": dynamic_summary.get("crypto_operations", 0),
                "reflection_usage": dynamic_summary.get("reflection_usage", 0),
                "native_code_usage": dynamic_summary.get("native_code_usage", 0),
                "accessibility_service_usage": dynamic_summary.get("accessibility_service_usage", 0),
                "yara_matches": ", ".join(s.get("yara_matches", [])),
                "key_flags": " | ".join(s.get("key_flags", []))
            })

        with output_path.open("w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(flat_rows)

        return output_path
