from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class Event:
    """Represents a single captured behavior from Frida."""
    source: str
    timestamp: float
    action: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class YaraMatch:
    """Represents a YARA rule match."""
    file: str
    matched_rules: List[str]


@dataclass
class Verdict:
    """Represents the suspicion score and decision."""
    score: int
    label: str  # benign | suspicious | malicious
    reasons: List[str] = field(default_factory=list)


@dataclass
class Report:
    """Represents a full structured analysis of an app."""
    package: str
    verdict: Verdict
    events: List[Event]
    yara_matches: List[YaraMatch] = field(default_factory=list)
    static_analysis: Optional[Dict[str, Any]] = None

@dataclass
class APKReportBuilder:
    package: str
    verdict: Verdict = field(default_factory=lambda: Verdict(score=0, label="benign"))
    events: List[Event] = field(default_factory=list)
    yara_matches: List[YaraMatch] = field(default_factory=list)
    static_analysis: Optional[Dict[str, Any]] = None

    def merge_hook_result(self, hook_result: Dict[str, Any]):
        normalized_events = []

        for e in hook_result.get("events", []):
            # Copy only expected fields
            normalized = {
                "source": e.get("source", "unknown"),
                "timestamp": e.get("timestamp", 0.0),
                "action": e.get("action") or e.get("event", "unknown"),
                "metadata": {}
            }

            # Move unexpected keys into metadata
            for k, v in e.items():
                if k not in {"source", "timestamp", "action", "event"}:
                    normalized["metadata"][k] = v

            normalized_events.append(Event(**normalized))

        self.events.extend(normalized_events)

        self.verdict.reasons.extend(hook_result.get("reasons", []))
        self.verdict.score += hook_result.get("score", 0)

        label = hook_result.get("verdict")
        if label == "malicious":
            self.verdict.label = "malicious"
        elif label == "suspicious" and self.verdict.label == "benign":
            self.verdict.label = "suspicious"

    def set_static(self, yara: List[YaraMatch], static: Dict[str, Any]):
        self.yara_matches = yara
        self.static_analysis = static

    def build(self) -> Report:
        return Report(
            package=self.package,
            verdict=self.verdict,
            events=self.events,
            yara_matches=self.yara_matches,
            static_analysis=self.static_analysis
        )

