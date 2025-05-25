from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


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


