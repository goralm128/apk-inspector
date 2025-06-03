from dataclasses import dataclass, field
from typing import Callable, List, Dict, Tuple, Optional, Any
from apk_inspector.utils.yara_utils import YaraMatchEvaluator
from apk_inspector.heuristics.static_heuristics import StaticHeuristicEvaluator
from apk_inspector.reports.models import Verdict
from apk_inspector.config.scoring_loader import load_scoring_profile
from pathlib import Path
from apk_inspector.utils.logger import get_logger

logger = get_logger()


@dataclass
class Rule:
    id: str
    description: str
    category: str
    weight: int
    condition: Callable[[dict], bool]
    tags: List[str] = field(default_factory=list)
    cvss: float = 0.0
    severity: str = "medium"
    disabled: bool = False


class RuleEngine:
    MALICIOUS_THRESHOLD = 80
    SUSPICIOUS_THRESHOLD = 40

    def __init__(self, rules: List[Rule], scoring_profile_path: Optional[Path] = None):
        self.rules = rules
        scoring_profile_path = scoring_profile_path or Path("config/scoring_profile.yaml")
        self._load_scoring(scoring_profile_path)

    def _load_scoring(self, path: Path):
        try:
            (
                self.CATEGORY_SCORE,
                self.TAG_SCORE,
                self.SEVERITY_SCORE,
                self.PATH_TYPE_SCORE
            ) = load_scoring_profile(path)

            # Normalize for consistent access
            self.CATEGORY_SCORE = {str(k).strip().lower(): v for k, v in self.CATEGORY_SCORE.items()}
            self.TAG_SCORE = {str(k).strip(): v for k, v in self.TAG_SCORE.items()}
            self.SEVERITY_SCORE = {str(k).strip().lower(): v for k, v in self.SEVERITY_SCORE.items()}
            self.PATH_TYPE_SCORE = {str(k).strip().lower(): v for k, v in self.PATH_TYPE_SCORE.items()}

            logger.info(f"[Scoring] Loaded {len(self.TAG_SCORE)} tag scores from: {path}")
            logger.debug(f"[Scoring] Loaded tag keys: {list(self.TAG_SCORE.keys())}")

        except Exception as e:
            logger.warning(f"[RuleEngine] Failed to load scoring profile: {e}. Using safe defaults.")
            self.CATEGORY_SCORE = {}
            self.TAG_SCORE = {}
            self.SEVERITY_SCORE = {}
            self.PATH_TYPE_SCORE = {}

    def _evaluate_static(self, static_info: Dict[str, Any]) -> Tuple[int, List[str]]:
        try:
            score, reasons = StaticHeuristicEvaluator.evaluate(static_info)
            return min(score, 20), [f"[STATIC] {r}" for r in reasons]
        except Exception as e:
            logger.exception("[RuleEngine] Static analysis failed")
            return 0, [f"[ERROR] Static analysis failure: {e}"]

    def _evaluate_dynamic(self, events: List[Dict[str, Any]]) -> Tuple[int, List[str], int, bool]:
        score = 0
        reasons = []
        high_risk_event_count = 0
        network_activity_detected = False

        for event in events:
            triggered_severities = []

            for rule in self.rules:
                if rule.disabled:
                    continue
                try:
                    if rule.condition(event):
                        triggered_severities.append(rule.severity)
                        metadata = event.setdefault("metadata", {})
                        metadata.setdefault("triggered_rules", []).append(rule.id)
                        metadata.setdefault("rule_severities", []).append(rule.severity)

                        if rule.cvss > 0:
                            score += int(rule.cvss)
                        else:
                            score += rule.weight + self.SEVERITY_SCORE.get(rule.severity, 0)

                        reasons.append(f"[{rule.severity.upper()}] Rule {rule.id}: {rule.description}")

                except Exception as e:
                    reasons.append(f"[WARN] Rule {rule.id} failed: {e}")

            if any(s in {"high", "critical"} for s in triggered_severities):
                event["metadata"]["risk_level"] = "high"
                high_risk_event_count += 1

            if event.get("metadata", {}).get("category") == "network":
                network_activity_detected = True

            path_type = event.get("path_type")
            if path_type:
                pts = self.PATH_TYPE_SCORE.get(str(path_type).strip().lower(), 0)
                if pts > 0:
                    score += pts
                    reasons.append(f"[DYNAMIC] Accessed {path_type} path: {event.get('path') or event.get('file')}")

        return score, reasons, high_risk_event_count, network_activity_detected

    def _evaluate_yara(self, yara_hits: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
        try:
            logger.info(f"[RuleEngine] Evaluating {len(yara_hits)} raw YARA hits")

            unique_hits = []
            seen = set()
            for hit in yara_hits:
                key = (hit.get("rule"), frozenset(hit.get("tags", [])))
                if key not in seen:
                    seen.add(key)
                    unique_hits.append(hit)

            score, reasons = YaraMatchEvaluator.evaluate(
                unique_hits,
                category_score=self.CATEGORY_SCORE,
                tag_score=self.TAG_SCORE,
                severity_score=self.SEVERITY_SCORE
            )

            logger.info(f"[RuleEngine] Deduplicated to {len(unique_hits)} YARA hits")
            logger.debug(f"[RuleEngine] Category keys: {list(self.CATEGORY_SCORE.keys())}")
            logger.debug(f"[RuleEngine] Tag keys: {list(self.TAG_SCORE.keys())}")
            logger.debug(f"[RuleEngine] Severity keys: {list(self.SEVERITY_SCORE.keys())}")
            return min(score, 10), [f"[YARA] {r}" for r in reasons]

        except Exception as e:
            logger.exception("[RuleEngine] YARA evaluation failed")
            return 0, [f"[ERROR] YARA evaluation failure: {e}"]

    def _label_from_score(self, total_score: int, dynamic_score: int = 0) -> str:
        if total_score >= self.MALICIOUS_THRESHOLD:
            return "malicious"
        elif total_score >= self.SUSPICIOUS_THRESHOLD or dynamic_score >= 30:
            return "suspicious"
        return "benign"

    def evaluate(
        self,
        events: List[Dict[str, Any]],
        static_info: Optional[Dict[str, Any]] = None,
        yara_hits: Optional[List[Dict[str, Any]]] = None
    ) -> Verdict:
        reasons: List[str] = []
        total_score = 0

        logger.debug(f"[RuleEngine] Starting evaluation with {len(events)} events and {len(yara_hits or [])} YARA hits")

        # --- Static ---
        static_score, static_reasons = (0, [])
        if static_info:
            static_score, static_reasons = self._evaluate_static(static_info)
        reasons.extend(static_reasons)

        # --- Dynamic ---
        dynamic_score, dynamic_reasons, high_risk_events, network_flag = (0, [], 0, False)
        if events:
            dynamic_score, dynamic_reasons, high_risk_events, network_flag = self._evaluate_dynamic(events)
        reasons.extend(dynamic_reasons)

        # --- YARA ---
        yara_score, yara_reasons = (0, [])
        if yara_hits:
            yara_score, yara_reasons = self._evaluate_yara(yara_hits)
        reasons.extend(yara_reasons)

        # --- Verdict ---
        total_score = static_score + dynamic_score + yara_score
        label = self._label_from_score(total_score, dynamic_score)

        logger.info(f"[RuleEngine] Final score: {total_score}, label: {label}")
        logger.debug(f"[RuleEngine] Reason breakdown: {reasons}")

        return Verdict(
            score=min(total_score, 100),
            label=label,
            reasons=reasons,
            high_risk_event_count=high_risk_events,
            network_activity_detected=network_flag
        )
