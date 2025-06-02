import json
from pathlib import Path
from typing import List, Dict


class JsonSummaryExporter:
    def __init__(self, output_path: Path):
        self.output_path = output_path

    def write(self, summaries: List[Dict[str, any]]) -> Path:
        with self.output_path.open("w", encoding="utf-8") as f:
            json.dump(summaries, f, indent=2, ensure_ascii=False)
        return self.output_path
