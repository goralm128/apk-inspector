from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from uuid import uuid4
from datetime import datetime
from apk_inspector.reports.schemas import YaraMatchModel


@dataclass
class Event:
    event_id: str = field(default_factory=lambda: str(uuid4()))
    source: str = "unknown"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="microseconds") + "Z")
    action: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Event':
        raw_meta = data.get('metadata', {})
        inner_meta = raw_meta.pop('metadata', {}) if isinstance(raw_meta, dict) else {}
        raw_meta.update(inner_meta)  # Flatten nested metadata

        return cls(
            source=data.get("source") or raw_meta.get("source_hook") or raw_meta.get("process_name") or "unknown",
            timestamp=data.get('timestamp') or datetime.now().isoformat(timespec="microseconds") + "Z",
            action=data.get('action', data.get('event', 'unknown')),
            metadata=raw_meta
        )
    
@dataclass
class HookResult:
    events: List[Event]
    verdict: str
    score: int
    reasons: List[str]
    yara_matches: List[YaraMatchModel]
    static_analysis: Dict[str, Any]   
    
@dataclass
class TriggeredRuleResult:
    rule_id: str
    severity: str
    cvss: float
    weight: int
    bonus: int
    classification: str
    description: str
    tags: List[str]
    event_id: Optional[str] = None

@dataclass
class Verdict:
    """Represents the suspicion score and decision."""
    score: int
    label: str  # benign | suspicious | malicious
    reasons: List[str]
    high_risk_event_count: int = 0
    network_activity_detected: bool = False
    cvss_risk_band: str = "Unknown"
    static_score: int = 0
    dynamic_score: int = 0
    yara_score: int = 0
    triggered_rule_results: List[TriggeredRuleResult] = field(default_factory=list)
    
@dataclass
class ApkSummary:
    apk_name: str
    apk_package: str
    sha256: str
    classification: str
    risk_score: int
    key_flags: List[str]
    dynamic_summary: Dict[str, int]
    yara_matches: List[str]
    top_tags: List[str] = field(default_factory=list)
    top_sources: List[str] = field(default_factory=list)
    yara_match_count: int = 0
    top_triggered_rules: List[str] = field(default_factory=list)
    cvss_risk_band: str = "Unknown"
    risk_breakdown: Dict[str, int] = field(default_factory=dict)
    error: str = ""

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "ApkSummary":
        return ApkSummary(
            apk_name=data.get("apk_name", "unknown.apk"),
            apk_package=data.get("apk_package", "unknown.package"),
            sha256=data.get("sha256", "N/A"),
            classification=data.get("classification", "unknown"),
            risk_score=data.get("risk_score", 0),
            key_flags=data.get("key_flags", []),
            dynamic_summary=data.get("dynamic_summary", {}),
            top_tags=data.get("top_tags", []),
            top_sources=data.get("top_sources", []),
            yara_matches=data.get("yara_matches", []),
            error=data.get("error", "")
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

