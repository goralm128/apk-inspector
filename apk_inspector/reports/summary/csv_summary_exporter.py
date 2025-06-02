import csv
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import List, Union, Dict, Any


class CsvSummaryExporter:
    def __init__(self, output_path: Path):
        self.output_path = output_path

    def write(self, summaries: List[Union[Dict[str, Any], object]]) -> Path:
        if not summaries:
            raise ValueError("No summary data to export.")

        processed = [
            asdict(s) if is_dataclass(s) else s for s in summaries
        ]

        for p in processed:
            p.setdefault("high_risk_event_count", 0)
            p.setdefault("network_activity_detected", False)
            p.setdefault("yara_match_count", 0)
            p.setdefault("cvss_risk_band", "Unknown")
            p.setdefault("top_triggered_rules", [])
            p["top_triggered_rules"] = ", ".join(p.get("top_triggered_rules", []))

        fieldnames = [
            "apk_name", "apk_package", "sha256", "classification", "risk_score",
            "cvss_risk_band", "yara_match_count", "top_triggered_rules",
            "high_risk_event_count", "network_activity_detected",
            "key_flags", "top_tags", "top_sources", "error"
        ]

        with self.output_path.open("w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(processed)

        return self.output_path