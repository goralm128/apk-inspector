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

        # Convert all dataclass instances to dicts
        processed = [
            asdict(s) if is_dataclass(s) else s for s in summaries
        ]

        fieldnames = list(processed[0].keys())

        with self.output_path.open("w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(processed)

        return self.output_path
