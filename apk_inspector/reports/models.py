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


