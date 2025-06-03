
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any
from apk_inspector.reports.models import Event, Verdict
from apk_inspector.reports.models import YaraMatchModel
from apk_inspector.reports.summary.dynamic_summary import summarize_dynamic_events
from apk_inspector.rules.apply import apply_rules
from apk_inspector.utils.scoring_utils import compute_cvss_band
from apk_inspector.config.scoring_loader import load_scoring_profile
from apk_inspector.rules.apply import apply_rules
from apk_inspector.config.defaults import DEFAULT_SCORING_PROFILE_PATH 

class APKReportBuilder:
    def __init__(self, package: str, apk_path: Path):
        self.package = package
        self.apk_path = apk_path
        self.verdict = Verdict(score=0, label="benign", reasons=[])
        self.events: List[Event] = []
        self.yara_matches: List[YaraMatchModel] = []
        self.static_analysis: Dict[str, Any] = {}

    def merge_hook_result(self, hook_result: Dict[str, Any]):
        for raw_event in hook_result.get("events", []):
            event = Event.from_dict(raw_event)

            # Inject extra fields
            event.metadata.setdefault("event_id", event.event_id)
            event.metadata.setdefault("process_name", raw_event.get("process_name", "unknown"))
            event.metadata.setdefault("pid", raw_event.get("pid", -1))
            event.metadata.setdefault("count", 1)  # For future aggregation

            self.events.append(event)

        # Handle verdict
        verdict = hook_result.get("verdict")
        if isinstance(verdict, Verdict):
            self.verdict = verdict
        else:
            self.verdict.reasons.extend(hook_result.get("reasons", []))
            self.verdict.score += hook_result.get("score", 0)
            self.verdict.label = hook_result.get("verdict", self.verdict.label)

    def set_static_analysis(self, yara_matches: List[Dict], static_result: Dict[str, Any]):
        if hasattr(static_result, "to_dict"):
            static_result = static_result.to_dict()
        self._static_analysis = static_result
        self._yara_matches = yara_matches
        
    def _get_hashes(self):
        data = self.apk_path.read_bytes()
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest()
        }

    def _summarize_events(self):
        return summarize_dynamic_events([e.__dict__ for e in self.events])

    def build(self) -> Dict[str, Any]:
        dynamic_summary = self._summarize_events()
        score, reasons = apply_rules([e.__dict__ for e in self.events], load_scoring_profile(DEFAULT_SCORING_PROFILE_PATH))
        self.verdict.score = score
        self.verdict.reasons = reasons
        self.verdict.cvss_risk_band = compute_cvss_band(score)
        report = {
            "apk_metadata": {
                "package_name": self.package,
                "analyzed_at": datetime.now(timezone.utc).isoformat(),
                "hash": self._get_hashes()
            },
            "static_analysis": self.static_analysis,
            "yara_matches": [m.to_dict() for m in self.yara_matches],
            "dynamic_analysis": {
                "events": [e.__dict__ for e in self.events],
                "summary": dynamic_summary
            },
            "classification": {
                "verdict": self.verdict.label,
                "score": self.verdict.score,
                "flags": self.verdict.reasons,
                "cvss_risk_band": self.verdict.cvss_risk_band
            }
        }
        return report