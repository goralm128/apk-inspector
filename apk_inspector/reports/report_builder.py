import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import asdict

from apk_inspector.reports.models import Event, Verdict, YaraMatchModel
from apk_inspector.reports.summary.dynamic_summary import summarize_dynamic_events
from apk_inspector.rules.rule_engine import RuleEngine
from apk_inspector.utils.event_utils import aggregate_events
from apk_inspector.utils.logger import get_logger
from apk_inspector.utils.yara_utils import serialize_yara_models, ensure_yara_models
from apk_inspector.reports.models import TriggeredRuleResult

logger = get_logger()


class APKReportBuilder:
    def __init__(self, package: str, apk_path: Path, rule_engine: RuleEngine):
        self.package = package
        self.apk_path = apk_path
        self.rule_engine = rule_engine

        self.verdict = Verdict(score=0, label="benign", reasons=[])
        self.events: List[Event] = []
        self.yara_matches: List[YaraMatchModel] = []
        self.static_analysis: Dict[str, Any] = {}
        self.hook_coverage: Dict[str, int] = {}
        self.hook_event_counts: Dict[str, int] = {}
        self.triggered_rule_results: List[TriggeredRuleResult] = []

    def merge_hook_result(self, hook_result: Dict[str, Any]):
        for raw_event in hook_result.get("events", []):
            try:
                event = Event.from_dict(raw_event)
                event.metadata.setdefault("process_name", raw_event.get("process_name", "unknown"))
                event.metadata.setdefault("pid", raw_event.get("pid", -1))
                event.metadata.setdefault("count", 1)
                self.events.append(event)
            except Exception as ex:
                logger.warning(f"[{self.package}] Failed to parse event: {ex}")

        self.hook_coverage = hook_result.get("hook_coverage", {})
        self.hook_event_counts = hook_result.get("hook_event_counts", {})
        verdict = hook_result.get("verdict")
        if isinstance(verdict, Verdict):
            self.verdict = verdict
        else:
            self.verdict.reasons.extend(hook_result.get("reasons", []))
            self.verdict.score += hook_result.get("score", 0)
            self.verdict.label = hook_result.get("verdict", self.verdict.label)

    def set_static_analysis(self, yara_matches: List[Dict[str, Any]], static_result: Dict[str, Any]):
        self.static_analysis = static_result.to_dict() if hasattr(static_result, "to_dict") else static_result
        self.yara_matches = ensure_yara_models(yara_matches)

    def _get_hashes(self) -> Dict[str, str]:
        try:
            data = self.apk_path.read_bytes()
            if len(data) > 200 * 1024 * 1024:
                logger.warning(f"[{self.package}] APK too large to hash in memory")
                return {"sha256": "N/A", "md5": "N/A"}
            return {
                "sha256": hashlib.sha256(data).hexdigest(),
                "md5": hashlib.md5(data).hexdigest()
            }
        except Exception as ex:
            logger.error(f"[{self.package}] Failed to hash APK: {ex}")
            return {"sha256": "N/A", "md5": "N/A"}

    def _event_dicts(self) -> List[Dict[str, Any]]:
        return [asdict(e) if hasattr(e, "__dataclass_fields__") else e.model_dump() for e in self.events]

    def _summarize_events(self) -> Dict[str, int]:
        return summarize_dynamic_events(self._event_dicts())

    def _evaluate(self) -> List[Dict[str, Any]]:
        logger.info(f"[{self.package}] Running evaluation on {len(self.events)} events")
        raw_events = self._event_dicts()
        aggregated_events = aggregate_events(raw_events, window_ms=100)
        yara_hits = serialize_yara_models(self.yara_matches)

        self.verdict = self.rule_engine.evaluate(
            events=aggregated_events,
            static_info=self.static_analysis,
            yara_hits=yara_hits,
            hook_coverage=self.hook_coverage
        )
        self.triggered_rule_results = getattr(self.verdict, "triggered_rule_results", [])
        logger.info(f"[{self.package}] Verdict: {self.verdict.label} | Score: {self.verdict.score}")
        return aggregated_events

    def _assemble_report(self, aggregated_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "apk_metadata": {
                "package_name": self.package,
                "analyzed_at": datetime.now(timezone.utc).isoformat(),
                "hash": self._get_hashes()
            },
            "static_analysis": self.static_analysis,
            "yara_matches": serialize_yara_models(self.yara_matches),
            "dynamic_analysis": {
                "original_events": self._event_dicts(),
                "aggregated_events": aggregated_events,
                "summary": self._summarize_events()
            },
            "triggered_rule_results": [asdict(r) for r in self.triggered_rule_results],
            "hook_coverage": self.hook_coverage,
            "hook_event_counts": self.hook_event_counts,
            "classification": {
                "verdict": self.verdict.label,
                "score": self.verdict.score,
                "flags": self.verdict.reasons,
                "cvss_risk_band": self.verdict.cvss_risk_band
            },
            "risk_breakdown": {
                "static_score": self.verdict.static_score,
                "dynamic_score": self.verdict.dynamic_score,
                "yara_score": self.verdict.yara_score,
                "total_score": self.verdict.score
            }
        }

    def build(self) -> Dict[str, Any]:
        logger.info(f"[{self.package}] Building full report...")
        try:
            aggregated_events = self._evaluate()
        except Exception as ex:
            logger.exception(f"[{self.package}] Evaluation error: {ex}")
            self.verdict = Verdict(score=0, label="error", reasons=["Evaluation failed"])
            aggregated_events = []
        return self._assemble_report(aggregated_events)
