from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from uuid import uuid4
from datetime import datetime
from apk_inspector.reports.schemas import YaraMatchModel


@dataclass
class Event:
    event_id: str = field(default_factory=lambda: str(uuid4()))
    source: str = "unknown"
    hook: str = "unknown"
    category: str = "uncategorized"
    action: str = "unknown"
    tags: List[str] = field(default_factory=list)
    score: int = 0
    label: str = "benign"
    justification: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="microseconds") + "Z")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Event':
        meta = data.get("metadata", {})
        tags = data.get("tags") or meta.get("tags", [])
        justification = data.get("justification", {})
        return cls(
            event_id=data.get("event_id", str(uuid4())),
            source=data.get("source", meta.get("source_hook", "unknown")),
            hook=data.get("hook", "unknown"),
            category=data.get("category", "uncategorized"),
            action=data.get("action", data.get("event", "unknown")),
            tags=tags if isinstance(tags, list) else [],
            score=data.get("score", 0),
            label=data.get("label", "benign"),
            justification=justification if isinstance(justification, dict) else {},
            metadata=meta,
            timestamp=data.get("timestamp", datetime.now().isoformat(timespec="microseconds") + "Z")
        )

@dataclass
class TriggeredRuleResult:
    rule_id: str
    severity: str
    severity_score: int
    cvss: float
    weight: int
    bonus: int
    description: str
    tags: List[str]
    category: str
    event_id: Optional[str] = None
    technique_id: Optional[str] = None # e.g., MITRE ATT&CK ID like T1059
    tactic: Optional[str] = None # e.g., MITRE ATT&CK tactic like Execution
    rule_source: str = "dynamic" # Could be: static | dynamic | yara
    verdict: Optional[str] = None       # Optional: used for final classification/labeling

@dataclass
class Verdict:
    score: int
    label: str
    reasons: List[str]
    high_risk_event_count: int = 0
    network_activity_detected: bool = False
    cvss_risk_band: str = "Unknown"
    static_score: int = 0
    dynamic_score: int = 0
    dynamic_rule_bonus: int = 0
    yara_score: int = 0
    hook_score: int = 0
    triggered_rule_results: List[TriggeredRuleResult] = field(default_factory=list)
    scoring_justification: Dict[str, int] = field(default_factory=dict)
    
@dataclass
class ApkSummary:
    # ─── Core APK Metadata ─────────────────────────────
    apk_name: str
    apk_package: str
    sha256: str

    # ─── Verdict & Classification ──────────────────────
    classification: str                      # benign | suspicious | malicious
    risk_score: int                          # Final numeric score (0–100)
    cvss_risk_band: str = "Unknown"          # Low / Medium / High / Critical

    # ─── Explanation Metadata ─────────────────────────
    key_flags: List[str] = field(default_factory=list)       # e.g. ["frida", "dlopen", "dex_load"]
    top_tags: List[str] = field(default_factory=list)        # Sorted by frequency / weight
    top_sources: List[str] = field(default_factory=list)     # e.g., ["hook_socket_io", "hook_dlopen"]
    top_triggered_rules: List[str] = field(default_factory=list)  # Most impactful rule IDs

    # ─── Scoring Analytics ─────────────────────────────
    risk_breakdown: Dict[str, int] = field(default_factory=dict)  # e.g., {"dex_loading": 15, "reflection": 10}
    scoring_justification: Dict[str, int] = field(default_factory=dict)  # e.g., {"token": 10, "jni": 10}

    # ─── Dynamic Execution Summary ─────────────────────
    dynamic_summary: Dict[str, int] = field(default_factory=dict)  # e.g., {"total_events": 123, "crypto_operations": 2}
    hook_coverage_percent: float = 0.0                             # % of hooks that fired during run
    hook_event_counts: Dict[str, int] = field(default_factory=dict)  # {"hook_socket_io": 12, "hook_exec_native": 3}
    behavioral_categories: List[str] = field(default_factory=list)   # Sorted top behaviors by category

    # ─── Threat Intelligence ───────────────────────────
    yara_matches: List[str] = field(default_factory=list)
    yara_match_count: int = 0

    # ─── MITRE ATT&CK Integration ──────────────────────
    mitre_mapping_summary: Dict[str, List[str]] = field(default_factory=dict)
    # Example:
    # {
    #   "Execution": ["T1059 - Command & Scripting Interpreter", "T1620 - Reflective Code Loading"],
    #   "Defense Evasion": ["T1211 - Exploitation for Defense Evasion"]
    # }

    # ─── Error / Notes ─────────────────────────────────
    error: str = ""

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "ApkSummary":
        return ApkSummary(
            apk_name=data.get("apk_name", "unknown.apk"),
            apk_package=data.get("apk_package", "unknown.package"),
            sha256=data.get("sha256", "N/A"),
            classification=data.get("classification", "unknown"),
            risk_score=data.get("risk_score", 0),
            cvss_risk_band=data.get("cvss_risk_band", "Unknown"),
            key_flags=data.get("key_flags", []),
            top_tags=data.get("top_tags", []),
            top_sources=data.get("top_sources", []),
            top_triggered_rules=data.get("top_triggered_rules", []),
            risk_breakdown=data.get("risk_breakdown", {}),
            scoring_justification=data.get("scoring_justification", {}),
            dynamic_summary=data.get("dynamic_summary", {}),
            hook_coverage_percent=data.get("hook_coverage_percent", 0.0),
            hook_event_counts=data.get("hook_event_counts", {}),
            behavioral_categories=data.get("behavioral_categories", []),
            yara_matches=data.get("yara_matches", []),
            yara_match_count=data.get("yara_match_count", 0),
            mitre_mapping_summary=data.get("mitre_mapping_summary", {}),
            error=data.get("error", "")
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)