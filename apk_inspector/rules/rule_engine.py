from dataclasses import dataclass, field, asdict
from typing import Callable, List, Dict, Tuple, Optional, Any
from apk_inspector.utils.yara_utils import YaraMatchEvaluator
from apk_inspector.heuristics.static_heuristics import StaticHeuristicEvaluator
from apk_inspector.reports.models import Verdict, TriggeredRuleResult
from apk_inspector.config.scoring_loader import load_scoring_profile
from apk_inspector.config.defaults import DEFAULT_SCORING_PROFILE_PATH
from apk_inspector.utils.logger import get_logger
from pathlib import Path
import json

logger = get_logger()

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

DEFAULT_HOOK_SCORE_TABLE = {
    "hook_socket_io": 5,
    "hook_exec_native": 7,
    "hook_dump_dex_from_mmap": 9,
    "hook_dlopen": 5,
    "hook_file_write": 3,
    "hook_get_accounts": 6
}


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
    DYNAMIC_BOOST_THRESHOLD = 30

    def __init__(self, rules: List[Rule], scoring_profile_path: Optional[Path] = None, thresholds_path: Optional[Path] = None):
        assert isinstance(rules, list) and rules, "No rules loaded!"
        self.rules = rules
        logger.info(f"[✓] Loaded {len(self.rules)} rules: {[r.id for r in self.rules]}")
        self._load_scoring(scoring_profile_path or DEFAULT_SCORING_PROFILE_PATH)
        self._load_thresholds(thresholds_path or CONFIG_DIR / "auto_thresholds.json")
        self.HOOK_SCORE_TABLE = DEFAULT_HOOK_SCORE_TABLE

    def _load_scoring(self, path: Path):
        try:
            self.CATEGORY_SCORE, self.TAG_SCORE, self.SEVERITY_SCORE, self.PATH_TYPE_SCORE = load_scoring_profile(path)
            self.CATEGORY_SCORE = {str(k).strip().lower(): v for k, v in self.CATEGORY_SCORE.items()}
            self.TAG_SCORE = {str(k).strip(): v for k, v in self.TAG_SCORE.items()}
            self.SEVERITY_SCORE = {str(k).strip().lower(): v for k, v in self.SEVERITY_SCORE.items()}
            self.PATH_TYPE_SCORE = {str(k).strip().lower(): v for k, v in self.PATH_TYPE_SCORE.items()}
            logger.info(f"[Scoring] Loaded scoring profile from: {path}")
        except Exception as ex:
            logger.warning(f"[RuleEngine] Failed to load scoring profile: {ex}. Using safe defaults.")
            self.CATEGORY_SCORE = {}
            self.TAG_SCORE = {}
            self.SEVERITY_SCORE = {}
            self.PATH_TYPE_SCORE = {}

    def _load_thresholds(self, path: Path):
        try:
            with path.open("r", encoding="utf-8") as f:
                thresholds = json.load(f)
            self.MALICIOUS_THRESHOLD = thresholds.get("malicious_threshold", 80)
            self.SUSPICIOUS_THRESHOLD = thresholds.get("suspicious_threshold", 40)
            self.DYNAMIC_BOOST_THRESHOLD = thresholds.get("dynamic_boost_threshold", 30)
            logger.info(f"[✓] Loaded thresholds from {path}: {thresholds}")
        except Exception as ex:
            logger.warning(f"[RuleEngine] Could not load thresholds: {ex}")

    def _calculate_bonus(self, rule: Rule) -> int:
        if rule.cvss > 0:
            return int(rule.cvss)
        base = rule.weight
        sev = self.SEVERITY_SCORE.get(rule.severity.lower(), 0)
        tag_bonus = sum(self.TAG_SCORE.get(tag, 0) for tag in rule.tags)
        cat_bonus = self.CATEGORY_SCORE.get(rule.category.lower(), 0)
        return base + sev + tag_bonus + cat_bonus

    def _apply_rules_to_event(self, event: Dict[str, Any]) -> Optional[Tuple[int, List[TriggeredRuleResult]]]:
        total_bonus, triggered = 0, []
        for rule in self.rules:
            if rule.disabled:
                continue
            try:
                if rule.condition(event):
                    bonus = self._calculate_bonus(rule)
                    total_bonus += bonus
                    result = TriggeredRuleResult(
                        rule_id=rule.id,
                        severity=rule.severity,
                        cvss=rule.cvss,
                        weight=rule.weight,
                        bonus=bonus,
                        classification=self.SEVERITY_SCORE.get(rule.severity.lower(), 0),
                        description=rule.description,
                        tags=rule.tags,
                        event_id=event.get("event_id", "")
                    )
                    triggered.append(result)
                    logger.debug(f"[RuleEngine] Rule {rule.id} triggered on event {event.get('event_id')}")
            except Exception as ex:
                logger.warning(f"[!] Rule {rule.id} evaluation error: {ex}")
        if not triggered:
            return None
        event.setdefault("metadata", {})["triggered_rule_details"] = [r.__dict__ for r in triggered]
        event["metadata"]["triggered_rules"] = [r.rule_id for r in triggered]
        return total_bonus, triggered

    def _evaluate_dynamic(self, events: List[Dict[str, Any]]) -> Tuple[int, List[str], int, bool, List[TriggeredRuleResult]]:
        total_score = 0
        reasons, rule_results = [], []
        high_risk, net_flag = 0, False
        for event in events:
            if not isinstance(event, dict):
                try:
                    event = asdict(event)
                except Exception as ex:
                    logger.warning(f"[RuleEngine] Skipping invalid event: {ex}")
                    continue
            metadata = event.setdefault("metadata", {})
            triggered = self._apply_rules_to_event(event)
            if triggered:
                bonus, triggered_rules = triggered
                total_score += bonus
                rule_results.extend(triggered_rules)
                reasons += [r.description for r in triggered_rules]
                severities = [r.severity for r in triggered_rules]
                if any(s in ("high", "critical") for s in severities):
                    metadata["risk_level"] = "high"
                    high_risk += 1
                else:
                    metadata["risk_level"] = max(severities, key=lambda s: self.SEVERITY_SCORE.get(s, 0), default="low")
            else:
                metadata["risk_level"] = "low"
        return total_score, reasons, high_risk, net_flag, rule_results

    def _evaluate_static(self, static_info: Dict[str, Any]) -> Tuple[int, List[str]]:
        try:
            score, reasons = StaticHeuristicEvaluator.evaluate(static_info)
            return min(score, 20), [f"[STATIC] {r}" for r in reasons]
        except Exception as ex:
            logger.exception("[RuleEngine] Static analysis failed")
            return 0, [f"[ERROR] Static analysis failure: {ex}"]

    def _evaluate_yara(self, yara_hits: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
        try:
            logger.info(f"[RuleEngine] Evaluating {len(yara_hits)} YARA hits")
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
            return min(score, 10), [f"[YARA] {r}" for r in reasons]
        except Exception as ex:
            logger.exception("[RuleEngine] YARA evaluation failed")
            return 0, [f"[ERROR] YARA evaluation failure: {ex}"]

    def _evaluate_hook_coverage(self, coverage: Dict[str, int]) -> Tuple[int, List[str]]:
        if not coverage:
            return 0, ["[HOOK COVERAGE] No hooks fired"]
        total_score = 0
        reasons = []
        for hook_name, count in coverage.items():
            weight = self.HOOK_SCORE_TABLE.get(hook_name, 1)
            score = weight * min(count, 5)
            total_score += score
            reasons.append(f"[HOOK] {hook_name} ×{count} → +{score}")
        return min(total_score, 12), reasons

    def _label_from_score(self, total_score: int, dynamic_score: int = 0) -> str:
        if total_score >= self.MALICIOUS_THRESHOLD:
            return "malicious"
        elif total_score >= self.SUSPICIOUS_THRESHOLD or dynamic_score >= self.DYNAMIC_BOOST_THRESHOLD:
            return "suspicious"
        return "benign"

    def score_event(self, event: Dict[str, Any]) -> Tuple[int, str, Dict[str, Any]]:
        score = 0
        justification = {
            "source": event.get("source", ""),
            "category_score": 0,
            "tags_score": 0,
            "classification_bonus": 0,
            "tag_matches": [],
            "classification": event.get("classification", "")
        }

        category = event.get("category", "")
        source = event.get("source", "")
        if category and source:
            cat_score = self.CATEGORY_SCORE.get(category, 0)
            score += cat_score
            justification["category_score"] = cat_score

        for tag in event.get("tags", []):
            tag_score = self.TAG_SCORE.get(tag, 0)
            if tag_score:
                score += tag_score
                justification["tags_score"] += tag_score
                justification["tag_matches"].append(tag)

        classification = event.get("classification", "")
        cls_score = self.TAG_SCORE.get(classification, 0)
        if cls_score:
            score += cls_score
            justification["classification_bonus"] = cls_score

        if score >= 50:
            label = "malicious"
        elif score >= 20:
            label = "suspicious"
        else:
            label = "benign"

        return score, label, justification
        
    def _compute_cvss_band(self, events: List[Dict[str, Any]]) -> str:
        cvss_scores = []
        for e in events:
            if not isinstance(e, dict):
                continue
            if e.get('hook') == 'frida_helpers':
                continue
            rule_details = e.get("metadata", {}).get("triggered_rule_details", [])
            for rule in rule_details:
                if isinstance(rule, dict):
                    cvss_scores.append(rule.get("cvss", 0.0))
        max_cvss = max(cvss_scores, default=0.0)
        if max_cvss >= 9.0: return "Critical"
        if max_cvss >= 7.0: return "High"
        if max_cvss >= 4.0: return "Medium"
        if max_cvss > 0.0: return "Low"
        return "Unknown"
    

    def evaluate(
        self,
        events: List[Dict[str, Any]],
        static_info: Optional[Dict[str, Any]] = None,
        yara_hits: Optional[List[Dict[str, Any]]] = None,
        hook_coverage: Optional[Dict[str, int]] = None
    ) -> Verdict:
        logger.debug(f"[RuleEngine] Evaluation started: {len(events)} events")
        static_score, static_reasons = self._evaluate_static(static_info) if static_info else (0, [])
        dynamic_score, dynamic_reasons, high_risk, net_flag, rule_results = self._evaluate_dynamic(events) if events else (0, [], 0, False, [])
        hook_score, hook_reasons = self._evaluate_hook_coverage(hook_coverage) if hook_coverage else (0, [])
        yara_score, yara_reasons = self._evaluate_yara(yara_hits) if yara_hits else (0, [])
        total_score = static_score + dynamic_score + hook_score + yara_score
        reasons = static_reasons + dynamic_reasons + yara_reasons + hook_reasons
        label = self._label_from_score(total_score, dynamic_score)
        logger.info(f"[RuleEngine] Final score={total_score}, label={label}")
        return Verdict(
            score=min(total_score, 100),
            label=label,
            reasons=reasons,
            high_risk_event_count=high_risk,
            network_activity_detected=net_flag,
            cvss_risk_band=self._compute_cvss_band(events),
            static_score=static_score,
            dynamic_score=dynamic_score,
            yara_score=yara_score,
            triggered_rule_results=rule_results
        )
