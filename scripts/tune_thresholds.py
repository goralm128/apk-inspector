
from apk_inspector.tuning.threshold_tuner import ThresholdTuner
from apk_inspector.reports.models import Verdict
import json
import sys
from pathlib import Path

def load_verdicts(path: Path) -> list[Verdict]:
    raw = json.loads(path.read_text(encoding='utf-8'))
    return [Verdict(**v) for v in raw if isinstance(v, dict) and 'score' in v]

if __name__ == "__main__":
    path = Path("output/combined_summary.json")
    verdicts = load_verdicts(path)
    
    tuner = ThresholdTuner(output_path=Path("config/auto_thresholds.json"))
    tuner.fit_from_verdicts(verdicts)
