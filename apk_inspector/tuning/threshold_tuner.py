import json
import numpy as np
from pathlib import Path
from typing import List, Dict, Optional
from apk_inspector.reports.models import Verdict
from apk_inspector.utils.logger import get_logger
from collections import Counter

logger = get_logger()

DEFAULT_OUTPUT_PATH = Path("config/auto_thresholds.json")


class ThresholdTuner:

    def __init__(self, output_path: Path = DEFAULT_OUTPUT_PATH):
        self.output_path = output_path

    def fit_from_verdicts(self, verdicts: List[Verdict]) -> Dict[str, int]:
        if not verdicts:
            raise ValueError("No verdicts provided for threshold tuning.")

        scores = [v.score for v in verdicts]
        dynamic_scores = [v.dynamic_score for v in verdicts]
        labels = [v.label for v in verdicts]

        logger.info(f"[Tuner] Analyzing {len(verdicts)} verdicts for auto-thresholding.")
        
        label_dist = Counter(labels)
        logger.info(f"[Tuner] Label distribution: {label_dist}")

        malicious_cutoff = suspicious_cutoff = None

        # Prefer label-based logic if sample size is decent
        if label_dist.get("malicious", 0) >= 3 and label_dist.get("suspicious", 0) >= 3:
            malicious_cutoff = min(v.score for v in verdicts if v.label == "malicious")
            suspicious_cutoff = min(v.score for v in verdicts if v.label == "suspicious")
            logger.info("[Tuner] Using label-based threshold calculation.")
        else:
            scores_np = np.array(scores)
            suspicious_cutoff = int(np.percentile(scores_np, 40))
            malicious_cutoff = int(np.percentile(scores_np, 80))
            logger.info("[Tuner] Using percentile-based threshold calculation.")

        dyn_scores_np = np.array(dynamic_scores)
        dynamic_boost_threshold = int(np.percentile(dyn_scores_np, 60))

        # Apply clamped safety bounds
        suspicious_cutoff = max(20, min(suspicious_cutoff, 60))
        malicious_cutoff = max(60, min(malicious_cutoff, 95))
        dynamic_boost_threshold = max(20, min(dynamic_boost_threshold, 40))

        logger.info(f"[Tuner] Clamped suspicious: {suspicious_cutoff}, "
                    f"malicious: {malicious_cutoff}, boost: {dynamic_boost_threshold}")

        thresholds = {
            "suspicious_threshold": suspicious_cutoff,
            "malicious_threshold": malicious_cutoff,
            "dynamic_boost_threshold": dynamic_boost_threshold
        }

        logger.info(f"[Tuner] Computed thresholds: {thresholds}")
        self._save_thresholds(thresholds)
        return thresholds

    def _save_thresholds(self, thresholds: Dict[str, int]):
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("w", encoding="utf-8") as f:
            json.dump(thresholds, f, indent=2)
        logger.info(f"[Tuner] Saved thresholds to {self.output_path.resolve()}")

    def load_thresholds(self) -> Optional[Dict[str, int]]:
        if not self.output_path.exists():
            logger.warning(f"[Tuner] Threshold file not found: {self.output_path}")
            return None
        try:
            with self.output_path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as ex:
            logger.error(f"[Tuner] Failed to load thresholds: {ex}")
            return None
