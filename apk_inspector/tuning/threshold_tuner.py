import json
import numpy as np
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from apk_inspector.reports.models import Verdict
from apk_inspector.utils.logger import get_logger

logger = get_logger()

DEFAULT_OUTPUT_PATH = Path("config/auto_thresholds.json")


class ThresholdTuner:
    def __init__(self, output_path: Path = DEFAULT_OUTPUT_PATH):
        self.output_path = output_path

    def fit_from_verdicts(self, verdicts: List[Verdict]) -> Dict[str, int]:
        """
        Analyze a list of Verdict objects and compute thresholds based on score distributions.
        Returns a dictionary with 'benign', 'suspicious', 'malicious' thresholds.
        """

        if not verdicts:
            raise ValueError("No verdicts provided for threshold tuning.")

        scores = [v.score for v in verdicts]
        dynamic_scores = [v.dynamic_score for v in verdicts]
        labels = [v.label for v in verdicts]

        logger.info(f"[Tuner] Analyzing {len(verdicts)} verdicts for auto-thresholding.")

        # Convert to numpy arrays
        scores_np = np.array(scores)
        dyn_scores_np = np.array(dynamic_scores)

        # Tune based on percentiles
        suspicious_cutoff = int(np.percentile(scores_np, 40))
        malicious_cutoff = int(np.percentile(scores_np, 80))

        dynamic_boost_threshold = int(np.percentile(dyn_scores_np, 60))

        # Save thresholds
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
