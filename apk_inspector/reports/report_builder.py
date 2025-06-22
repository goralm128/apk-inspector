import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Tuple
from dataclasses import asdict, is_dataclass

from apk_inspector.reports.models import Event, Verdict, YaraMatchModel, TriggeredRuleResult
from apk_inspector.reports.summary.dynamic_summary import summarize_dynamic_events
from apk_inspector.rules.rule_engine import RuleEngine
from apk_inspector.utils.event_utils import aggregate_events
from apk_inspector.utils.logger import get_logger
from apk_inspector.utils.yara_utils import serialize_yara_models, ensure_yara_models

logger = get_logger()

class APKReportBuilder:
    def __init__(self, package: str, apk_path: Path, rule_engine: RuleEngine):
        self.package = package
        self.apk_path = apk_path.resolve()
        self.rule_engine = rule_engine
        self.hook_metadata: Dict[str, Any] = {}
        self.reset()

    def reset(self):
        """Reset internal state for reuse across APKs."""
        self.verdict = Verdict(score=0, label="benign", reasons=[])
        self.events: List[Event] = []
        self.yara_matches: List[YaraMatchModel] = []
        self.static_analysis: Dict[str, Any] = {}
        self.hook_event_counts: Dict[str, int] = {}
        self.triggered_rule_results: List[TriggeredRuleResult] = []

    def set_hook_metadata(self, hook_metadata_map: Dict[str, Any]):
        self.hook_metadata = hook_metadata_map
    
    def merge_hook_result(self, hook_result: Dict[str, Any]) -> None:
        """Integrate dynamic hook results."""
        for raw_event in hook_result.get("events", []):
            try:
                event = Event.from_dict(raw_event)
                event.metadata.setdefault("process_name", raw_event.get("process_name", "unknown"))
                event.metadata.setdefault("pid", raw_event.get("pid", -1))
                event.metadata.setdefault("count", 1)
                self.events.append(event)
            except Exception as ex:
                logger.warning(f"[{self.package}] Failed to parse event: {ex}")

        self.hook_event_counts.update(hook_result.get("hook_event_counts", {}))

        verdict = hook_result.get("verdict")
        if isinstance(verdict, Verdict):
            self.verdict = verdict
        else:
            self.verdict.reasons.extend(hook_result.get("reasons", []))
            self.verdict.score += hook_result.get("score", 0)
            self.verdict.label = hook_result.get("verdict", self.verdict.label)

    def set_static_analysis(self, yara_matches: List[Dict[str, Any]], static_result: Dict[str, Any]) -> None:
        self.static_analysis = static_result.to_dict() if hasattr(static_result, "to_dict") else static_result
        self.yara_matches = ensure_yara_models(yara_matches)

    def _get_hashes(self) -> Dict[str, str]:
        try:
            sha256 = hashlib.sha256()
            md5 = hashlib.md5()
            with self.apk_path.open("rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
                    md5.update(chunk)
            return {
                "sha256": sha256.hexdigest(),
                "md5": md5.hexdigest()
            }
        except Exception as ex:
            logger.error(f"[{self.package}] Failed to hash APK: {ex}")
            return {"sha256": "N/A", "md5": "N/A"}

    def _event_dicts(self) -> List[Dict[str, Any]]:
        return [asdict(e) if is_dataclass(e) else e.model_dump() for e in self.events]

    def _summarize_events(self) -> Dict[str, int]:
        return summarize_dynamic_events(self._event_dicts())

    def _calculate_hook_coverage_percent(self) -> float:
        if not self.hook_metadata:
            return 0.0

        known_hooks = set(self.hook_metadata.keys())
        fired_hooks = {hook for hook in self.hook_event_counts if hook in known_hooks and self.hook_event_counts[hook] > 0}

        if not known_hooks:
            return 0.0

        coverage = (len(fired_hooks) / len(known_hooks)) * 100
        return round(min(coverage, 100.0), 2)  # Cap at 100%

    def _evaluate(self) -> Tuple[List[Dict[str, Any]], Verdict, List[TriggeredRuleResult]]:
        logger.info(f"[{self.package}] Running evaluation on {len(self.events)} events")

        raw_events = self._event_dicts()
        aggregated_events = aggregate_events(raw_events, window_ms=100)
        yara_hits = serialize_yara_models(self.yara_matches)

        verdict = self.rule_engine.evaluate(
            events=aggregated_events,
            static_info=self.static_analysis,
            yara_hits=yara_hits,
            hook_coverage=self.hook_event_counts  # still supported param
        )
        rule_results = getattr(verdict, "triggered_rule_results", [])
        logger.info(f"[{self.package}] Verdict: {verdict.label} | Score: {verdict.score}")
        return aggregated_events, verdict, rule_results

    def _assemble_report(
        self, aggregated_events: List[Dict[str, Any]], verdict: Verdict, rule_results: List[TriggeredRuleResult]
    ) -> Dict[str, Any]:
        return {
            "apk_metadata": {
                "package_name": self.package,
                "apk_name": self.apk_path.name,
                "apk_path": str(self.apk_path),
                "analyzed_at": datetime.now(timezone.utc).isoformat(),
                "hash": self._get_hashes(),
                "generated_by": "apk_inspector v1.0"
            },
            "static_analysis": self.static_analysis,
            "yara_matches": serialize_yara_models(self.yara_matches),
            "dynamic_analysis": {
                "original_events": self._event_dicts(),
                "aggregated_events": aggregated_events,
                "summary": self._summarize_events()
            },
            "triggered_rule_results": [asdict(r) for r in rule_results],
            "hook_event_counts": self.hook_event_counts,
            "hook_coverage_percent": self._calculate_hook_coverage_percent(),
            "report_summary": {
                "classification": {
                    "verdict": verdict.label,
                    "score": verdict.score,
                    "flags": verdict.reasons,
                    "cvss_risk_band": verdict.cvss_risk_band
                },
                "risk_breakdown": {
                    "static_score": verdict.static_score,
                    "dynamic_score": verdict.dynamic_score,
                    "dynamic_rule_bonus": verdict.dynamic_rule_bonus,
                    "yara_score": verdict.yara_score,
                    "hook_score": verdict.hook_score,
                    "total_score": verdict.score
                }
            }
        }
    
    def build(self) -> Dict[str, Any]:
        logger.info(f"[{self.package}] Building full report...")
        try:
            aggregated_events, verdict, rule_results = self._evaluate()
            self.verdict = verdict
            self.triggered_rule_results = rule_results
        except Exception as ex:
            logger.exception(f"[{self.package}] Evaluation error: {ex}")
            self.verdict = Verdict(score=0, label="error", reasons=["Evaluation failed"])
            aggregated_events = []
        return self._assemble_report(aggregated_events, self.verdict, self.triggered_rule_results)
