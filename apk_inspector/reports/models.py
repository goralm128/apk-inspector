from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any


@dataclass
class Event:
    source: str
    timestamp: str  # use ISO string
    action: str
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class YaraMatch:
    file: str
    rule: str
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    strings: List = field(default_factory=list)
    namespace: str = ""
   
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "YaraMatch":
        return cls(
            file=data.get("file", ""),
            rule=data.get("rule", ""),
            tags=data.get("tags", []),
            meta=data.get("meta", {}),
            strings=data.get("strings", []),
            namespace=data.get("namespace", "")
        )
    
@dataclass
class HookResult:
    events: List[Event]
    verdict: str
    score: int
    reasons: List[str]
    yara_matches: List[YaraMatch]
    static_analysis: Dict[str, Any]   


@dataclass
class Verdict:
    """Represents the suspicion score and decision."""
    score: int
    label: str  # benign | suspicious | malicious
    reasons: List[str] = field(default_factory=list)
    

@dataclass
class ApkSummary:
    apk_name: str
    apk_package: str
    sha256: str
    classification: str
    risk_score: int
    key_flags: List[str] = field(default_factory=list)
    dynamic_summary: Dict[str, Any] = field(default_factory=dict)
    top_tags: List[str] = field(default_factory=list)
    top_sources: List[str] = field(default_factory=list)
    yara_matches: List[str] = field(default_factory=list)
    error: str = ""  # optional

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

