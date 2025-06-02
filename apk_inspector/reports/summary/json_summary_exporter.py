import json
from pathlib import Path
from typing import List, Dict


class JsonSummaryExporter:
    def __init__(self, output_path: Path):
        self.output_path = output_path

    def write(self, summaries: List[Dict[str, Any]]) -> Path:
        for summary in summaries:
            summary.setdefault("high_risk_event_count", 0)
            summary.setdefault("network_activity_detected", False)
            summary.setdefault("yara_match_count", 0)
            summary.setdefault("cvss_risk_band", "Unknown")
            summary.setdefault("top_triggered_rules", [])
        with self.output_path.open("w", encoding="utf-8") as f:
            json.dump(summaries, f, indent=2, ensure_ascii=False)
        return self.output_path

