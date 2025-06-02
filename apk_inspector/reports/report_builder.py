from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from apk_inspector.reports.models import Event, YaraMatch, Verdict
import hashlib
from apk_inspector.reports.summary.dynamic_summary import summarize_dynamic_events

class APKReportBuilder:
    def __init__(self, package: str, apk_path: Path):
        self.package = package
        self.apk_path = apk_path
        self.verdict = Verdict(score=0, label="benign", reasons=[])
        self.events: List[Event] = []
        self.yara_matches: List[YaraMatch] = []
        self.static_analysis: Dict[str, Any] = {}

    def merge_hook_result(self, hook_result: Dict[str, Any]):
        for e in hook_result.get("events", []):
            normalized = {
                "source": e.get("source", "unknown"),
                "timestamp": e.get("timestamp", "1970-01-01T00:00:00Z"),
                "action": e.get("action") or e.get("event", "unknown"),
                "metadata": {k: v for k, v in e.items() if k not in {"source", "timestamp", "action", "event"}}
            }
            self.events.append(Event(**normalized))

        verdict = hook_result.get("verdict")
        if isinstance(verdict, Verdict):
            self.verdict = verdict
        else:
            # fallback to legacy dict form
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
        report = {
            "apk_metadata": {
                "package_name": self.package,
                "analyzed_at": datetime.utcnow().isoformat() + "Z",
                "hash": self._get_hashes()
            },
            "static_analysis": self.static_analysis,
            "yara_matches": [
                m.to_dict() if isinstance(m, YaraMatch) else m
                for m in self.yara_matches
            ],
            "dynamic_analysis": {
                "events": [e.__dict__ for e in self.events],
                "summary": self._summarize_events()
            },
            "classification": {
                "verdict": self.verdict.label,
                "score": min(self.verdict.score, 100),
                "flags": self.verdict.reasons
            }
        }
        
        return report
