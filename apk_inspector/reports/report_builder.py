import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

from apk_inspector.reports.models import Event, Verdict, YaraMatchModel
from apk_inspector.reports.summary.dynamic_summary import summarize_dynamic_events
from apk_inspector.rules.rule_engine import RuleEngine
from apk_inspector.utils.event_utils import aggregate_events
from apk_inspector.utils.logger import get_logger
from apk_inspector.utils.yara_utils import serialize_yara_models, ensure_yara_models

logger = get_logger()


class APKReportBuilder:
    """
    Builds a detailed security report for a given APK file.
    Handles static and dynamic results, applies scoring rules, and assembles structured output.
    """

    def __init__(self, package: str, apk_path: Path, rule_engine: RuleEngine):
        self.package = package
        self.apk_path = apk_path
        self.rule_engine = rule_engine

        self.verdict = Verdict(score=0, label="benign", reasons=[])
        self.events: List[Event] = []
        self.yara_matches: List[YaraMatchModel] = []
        self.static_analysis: Dict[str, Any] = {}

    def merge_hook_result(self, hook_result: Dict[str, Any]):
        """
        Integrate dynamic events and optional verdict from hook execution results.
        """
        for raw_event in hook_result.get("events", []):
            event = Event.from_dict(raw_event)
            event.metadata.setdefault("process_name", raw_event.get("process_name", "unknown"))
            event.metadata.setdefault("pid", raw_event.get("pid", -1))
            event.metadata.setdefault("count", 1)
            self.events.append(event)

        verdict = hook_result.get("verdict")
        if isinstance(verdict, Verdict):
            self.verdict = verdict
        else:
            self.verdict.reasons.extend(hook_result.get("reasons", []))
            self.verdict.score += hook_result.get("score", 0)
            self.verdict.label = hook_result.get("verdict", self.verdict.label)

    def set_static_analysis(self, yara_matches: List[Dict[str, Any]], static_result: Dict[str, Any]):
        """
        Store static analysis results and validated YARA matches.
        """
        self.static_analysis = static_result.to_dict() if hasattr(static_result, "to_dict") else static_result
        self.yara_matches = ensure_yara_models(yara_matches)

    def _get_hashes(self) -> Dict[str, str]:
        """
        Compute SHA256 and MD5 hashes of the APK file.
        """
        try:
            data = self.apk_path.read_bytes()
            if len(data) > 200 * 1024 * 1024:  # 200MB limit
                logger.warning(f"[{self.package}] APK too large for in-memory hashing: {self.apk_path}")
                return {"sha256": "N/A", "md5": "N/A"}
            return {
                "sha256": hashlib.sha256(data).hexdigest(),
                "md5": hashlib.md5(data).hexdigest()
            }
        except Exception as e:
            logger.error(f"[{self.package}] Failed to read APK for hashing: {e}")
            return {"sha256": "N/A", "md5": "N/A"}

    def _event_dicts(self) -> List[Dict[str, Any]]:
        """
        Return event objects as dictionaries.
        """
        return [e.model_dump() if hasattr(e, "model_dump") else e.__dict__ for e in self.events]

    def _summarize_events(self) -> Dict[str, int]:
        """
        Summarize categories and counts from collected events.
        """
        return summarize_dynamic_events(self._event_dicts())

    def _evaluate(self) -> List[Dict[str, Any]]:
        """
        Run rule engine against aggregated events and store final verdict.
        """
        logger.info(f"[{self.package}] Starting evaluation with {len(self.events)} raw events...")

        raw_events = self._event_dicts()
        aggregated_events = aggregate_events(raw_events, window_ms=100)

        logger.info(f"[{self.package}] {len(aggregated_events)} events after aggregation.")

        yara_hits = serialize_yara_models(self.yara_matches)

        logger.debug(f"[{self.package}] Evaluating with {len(yara_hits)} YARA matches...")
        self.verdict = self.rule_engine.evaluate(
            events=aggregated_events,
            static_info=self.static_analysis,
            yara_hits=yara_hits
        )

        logger.info(f"[{self.package}] Final verdict: {self.verdict.label} | Score: {self.verdict.score}")
        return aggregated_events

    def _assemble_report(self, aggregated_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build the final structured JSON report.
        """
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
            "classification": {
                "verdict": self.verdict.label,
                "score": self.verdict.score,
                "flags": self.verdict.reasons,
                "cvss_risk_band": self.verdict.cvss_risk_band
            }
        }

    def build(self) -> Dict[str, Any]:
        """
        Generate the full report with verdict and event analysis.
        """
        logger.info(f"[{self.package}] Starting report build...")
        try:
            aggregated_events = self._evaluate()
        except Exception as e:
            logger.exception(f"[{self.package}] Evaluation failed: {e}")
            self.verdict = Verdict(score=0, label="error", reasons=["Evaluation failed"])
            aggregated_events = []

        return self._assemble_report(aggregated_events)
