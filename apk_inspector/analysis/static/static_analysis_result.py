from dataclasses import dataclass, field
from typing import Dict, List, Any


@dataclass
class StaticAnalysisResult:
    manifest_analysis: Dict[str, Any] = field(default_factory=dict)
    static_warnings: List[Dict[str, Any]] = field(default_factory=list)
    string_matches: List[str] = field(default_factory=list)
    certificate: Dict[str, Any] = field(default_factory=dict)
    strings_xml_issues: List[Dict[str, Any]] = field(default_factory=list)
    log_leaks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest_analysis": self.manifest_analysis,
            "static_warnings": self.static_warnings,
            "string_matches": self.string_matches,
            "certificate": self.certificate,
            "strings_xml_issues": self.strings_xml_issues,
            "log_leaks": self.log_leaks
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StaticAnalysisResult":
        return cls(
            manifest_analysis=data.get("manifest_analysis", {}),
            static_warnings=data.get("static_warnings", []),
            string_matches=data.get("string_matches", []),
            certificate=data.get("certificate", {}),
            strings_xml_issues=data.get("strings_xml_issues", []),
            log_leaks=data.get("log_leaks", [])
        )
