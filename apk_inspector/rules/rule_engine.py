from dataclasses import dataclass, field, asdict
from typing import Callable, List, Dict, Tuple, Optional, Any
from apk_inspector.utils.yara_utils import YaraMatchEvaluator
from apk_inspector.heuristics.static_heuristics import StaticHeuristicEvaluator
from apk_inspector.reports.models import Verdict, TriggeredRuleResult
from apk_inspector.config.scoring_loader import load_scoring_profile
from apk_inspector.utils.scoring_utils import compute_cvss_band
from apk_inspector.config.defaults import DEFAULT_SCORING_PROFILE_PATH
from apk_inspector.tuning.threshold_tuner import ThresholdTuner
from apk_inspector.utils.logger import get_logger
from pathlib import Path
import json
from datetime import datetime
from collections import defaultdict
from math import log2

logger = get_logger()

def default_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

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
    MALICIOUS_THRESHOLD = 75
    SUSPICIOUS_THRESHOLD = 35
    DYNAMIC_BOOST_THRESHOLD = 28

    def __init__(self, rules: List[Rule], scoring_profile_path: Optional[Path] = None, 
                 thresholds_path: Optional[Path] = None, known_tags: Optional[List[str]] = None):
        assert isinstance(rules, list) and rules, "No rules loaded!"
        self.rules = rules
        logger.info(f"[✓] Loaded {len(self.rules)} rules: {[r.id for r in self.rules]}")
        self._load_scoring(scoring_profile_path or DEFAULT_SCORING_PROFILE_PATH)
        self._load_thresholds(thresholds_path or CONFIG_DIR / "auto_thresholds.json")
        self.HOOK_SCORE_TABLE = DEFAULT_HOOK_SCORE_TABLE
        self.KNOWN_TAGS = set(known_tags) if known_tags else set()
        
    def set_tag_rules(self, tag_rules: Dict[str, List[str]]):
        self.KNOWN_TAGS = set(tag_rules.keys())
        logger.info(f"[RuleEngine] Known tags updated: {len(self.KNOWN_TAGS)} tags")

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
            tuner = ThresholdTuner(output_path=path)
            thresholds = tuner.load_thresholds()
            if thresholds:
                self.MALICIOUS_THRESHOLD = thresholds.get("malicious_threshold", 75)
                self.SUSPICIOUS_THRESHOLD = thresholds.get("suspicious_threshold", 35)
                self.DYNAMIC_BOOST_THRESHOLD = thresholds.get("dynamic_boost_threshold", 28)
                logger.info(f"[✓] Loaded thresholds from tuner: {thresholds}")
            else:
                logger.warning("[RuleEngine] Using default fallback thresholds.")
        except Exception as ex:
            logger.warning(f"[RuleEngine] Could not load thresholds via tuner: {ex}")

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
        event_id = event.get("event_id", "unknown")

        for rule in self.rules:
            if rule.disabled:
                logger.info(f"[RuleEngine] Skipping disabled rule: {rule.id}")
                continue

            # ─── Validation for Category and Tags ─────────────────────────────
            if rule.category.lower() not in self.CATEGORY_SCORE:
                logger.warning(f"[RuleEngine] ⚠ Rule {rule.id} has unknown category: '{rule.category}'")

            unknown_tags = [t for t in rule.tags if t not in self.KNOWN_TAGS]
            if unknown_tags:
                logger.warning(f"[RuleEngine] ⚠ Rule {rule.id} contains unknown tags: {unknown_tags}")

            try:
                if rule.condition(event):
                    bonus = self._calculate_bonus(rule)
                    total_bonus += bonus
                    result = TriggeredRuleResult(
                        rule_id=rule.id,
                        severity=rule.severity,
                        severity_score=self.SEVERITY_SCORE.get(rule.severity.lower(), 0),
                        cvss=rule.cvss,
                        weight=rule.weight,
                        bonus=bonus,
                        description=rule.description,
                        tags=rule.tags,
                        category=rule.category,
                        event_id=event_id,
                        rule_source="dynamic"
                    )
                    triggered.append(result)
                    logger.info(f"[RuleEngine] ✅ Rule {rule.id} triggered on event {event_id} → bonus: {bonus}")
                else:
                    logger.debug(f"[RuleEngine] ❌ Rule {rule.id} did not match event {event_id}")
            except Exception as ex:
                logger.warning(f"[RuleEngine] ⚠ Rule {rule.id} raised exception on event {event_id}: {ex}")

        if not triggered:
            logger.info(f"[RuleEngine] No rules triggered for event {event_id}")

        if triggered:
            event.setdefault("metadata", {})["triggered_rule_details"] = [r.__dict__ for r in triggered]
            event["metadata"]["triggered_rules"] = [r.rule_id for r in triggered]
            return total_bonus, triggered
        else:
            return None


    def _evaluate_dynamic(self, events: List[Dict]) -> Tuple[int, int, List[str], int, bool, 
                                                             List[TriggeredRuleResult], Dict[str, int]]:
        reasons = []
        rule_results = []
        high_risk = 0
        net_flag = False
        event_count = defaultdict(int)
        seen_categories = set()
        combo_applied = False
        scoring_justification = defaultdict(int)

        raw_dynamic = 0
        raw_rule_bonus = 0
  
        for idx, evt in enumerate(events):
            triggered = self._apply_rules_to_event(evt)
            if not triggered:
                evt.setdefault("metadata", {})["risk_level"] = "low"
                continue

            bonus, rules = triggered
            raw_rule_bonus += bonus

            # Track severity levels for later decision
            severities = [r.severity.lower() for r in rules]
            medium_severity_count = 0

            for r in rules:
                rule_id = r.rule_id
                event_count[rule_id] += 1
                seen_categories.add(r.category)

                sev = r.severity.lower()
                sev_factor = self.SEVERITY_SCORE.get(sev, 1)
                freq = max(event_count[rule_id], 2)  # log2(2) = 1 minimum score factor
                scaled = int(r.weight * sev_factor * log2(freq))
                scaled = min(scaled, 15)
                #raw_dynamic += scaled
                #scoring_justification[rule_id] += scaled
                
                # Accumulate dynamic score from all severities, scaled differently
                if sev in ("critical", "high"):
                    raw_dynamic += scaled
                    scoring_justification[rule_id] += scaled
                elif sev == "medium":
                    bonus_score = int(scaled * 0.5)
                    raw_dynamic += bonus_score
                    scoring_justification[rule_id] += bonus_score
                elif sev == "low":
                    bonus_score = int(scaled * 0.25)
                    raw_dynamic += bonus_score
                    scoring_justification[rule_id] += bonus_score
            
                # Collect unique descriptions
                if r.description not in reasons:
                    reasons.append(r.description)

            # Risk classification
            if any(sev in ("high", "critical") for sev in severities):
                evt["metadata"]["risk_level"] = "high"
                high_risk += 1
            else:
                lvl = max(severities, key=lambda s: self.SEVERITY_SCORE.get(s, 0), default="low")
                evt["metadata"]["risk_level"] = lvl

            # Heuristic combo boost
            if not combo_applied and {"reflection", "dex_load", "http"}.issubset(set(evt.get("tags", []))):
                raw_dynamic += 15
                reasons.append("[COMBO] Reflection + Dex + Network")
                combo_applied = True

            # Behavioral bonus for medium severity
            if medium_severity_count >= 2:
                raw_dynamic += 5
                reasons.append("[BEHAVIOR] Medium-severity behavior present")

            rule_results.extend(rules)

        # Bonus for category diversity
        if len(seen_categories) >= 3:
            raw_dynamic += 10
            reasons.append(f"[BEHAVIOR] Diverse categories: {', '.join(seen_categories)}")
            
        logger.info(f"[RuleEngine] Dynamic analysis: {len(events)} events, {len(rule_results)} rules triggered, "
                    f"raw_dynamic={raw_dynamic}, raw_rule_bonus={raw_rule_bonus}, high_risk={high_risk}, "  
                    f"net_flag={net_flag}, event_count={dict(event_count)}")
        # Normalize dynamic score and rule bonus
        dyn_scaled = int(min(raw_dynamic, 100) * 0.5)  # normalize to 0–50
        dyn_bonus = min(raw_rule_bonus, 20) # Max 20
        logger.info(f"[RuleEngine] Scaled dynamic score: {dyn_scaled}, Rule bonus: {dyn_bonus}")
        return dyn_scaled, dyn_bonus, reasons, high_risk, net_flag, rule_results, scoring_justification


    def _evaluate_static(self, static_info: Dict[str, Any]) -> Tuple[int, List[str]]:
        try:
            score, reasons = StaticHeuristicEvaluator.evaluate(static_info)
            return score, [f"[STATIC] {r}" for r in reasons]
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
            return score, [f"[YARA] {r}" for r in reasons]
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
        
    def _compute_cvss_band(self, rules: List[TriggeredRuleResult]) -> str:
        cvss_scores = [r.cvss for r in rules if isinstance(r, TriggeredRuleResult)]
        max_cvss = max(cvss_scores, default=0.0)
        return compute_cvss_band(max_cvss)
    
    def evaluate(
        self,
        events: List[Dict[str, Any]],
        static_info: Optional[Dict[str, Any]] = None,
        yara_hits: Optional[List[Dict[str, Any]]] = None,
        hook_coverage: Optional[Dict[str, int]] = None
    ) -> Verdict:

        logger.info(f"[RuleEngine] Evaluation started: {len(events)} events")

        static_score, static_reasons = self._evaluate_static(static_info) if static_info else (0, [])
        dynamic_scaled_score, dynamic_rule_bonus, dynamic_reasons, high_risk, net_flag, rule_results, scoring_justification = self._evaluate_dynamic(events)
        hook_score, hook_reasons = self._evaluate_hook_coverage(hook_coverage) if hook_coverage else (0, [])
        yara_score, yara_reasons = self._evaluate_yara(yara_hits) if yara_hits else (0, [])

        logger.info(f"[RuleEngine] Static score: {static_score}, Dynamic score: {dynamic_scaled_score}, YARA score: {yara_score}, Hook score: {hook_score}")
        total_score = static_score + dynamic_scaled_score + dynamic_rule_bonus + yara_score
        capped_total_score = min(total_score, 100)

        all_reasons = static_reasons + dynamic_reasons + yara_reasons + hook_reasons
        
        if hook_score == 0:
            all_reasons.append("[⚠DYNAMIC] No hooks fired – analysis coverage may be incomplete")
        elif hook_score < 5:
            all_reasons.append("[ℹDYNAMIC] Limited hook coverage")
        
        label = self._label_from_score(capped_total_score, dynamic_scaled_score)
        logger.info(f"[RuleEngine] Final score={capped_total_score}, label={label}, dynamic_scaled_score={dynamic_scaled_score}")

        if not rule_results:
            logger.warning("[RuleEngine] No rules were triggered — check hook coverage and rule effectiveness.")
            
        cvss_band = self._compute_cvss_band(rule_results)

        return Verdict(
            score=capped_total_score,
            label=label,
            reasons=all_reasons,
            high_risk_event_count=high_risk,
            network_activity_detected=net_flag,
            cvss_risk_band=cvss_band,
            static_score=static_score,
            dynamic_score=dynamic_scaled_score,
            dynamic_rule_bonus=dynamic_rule_bonus,
            yara_score=yara_score,
            hook_score=hook_score,
            triggered_rule_results=rule_results,
            scoring_justification=scoring_justification
        )
