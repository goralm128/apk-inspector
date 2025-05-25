import yara
from pathlib import Path
import pandas as pd
from typing import List, Dict, Any


class YaraScanner:
    def __init__(self, rules_dir: Path = Path("yara_rules")):
        self.rules_dir = rules_dir
        self.rules = self._compile_yara_rules()

    def _compile_yara_rules(self) -> List[yara.Rules]:
        if not self.rules_dir.exists():
            print(f"[WARN] YARA rules directory not found: {self.rules_dir}")
            return []

        compiled_rules = []
        for rule_file in self.rules_dir.glob("*.yar"):
            try:
                print(f"[INFO] Compiling YARA rule: {rule_file.name}")
                compiled_rules.append(yara.compile(filepath=str(rule_file)))
            except Exception as e:
                print(f"[ERROR] Failed to compile {rule_file}: {e}")
        return compiled_rules

    def scan_directory(self, target_dir: Path) -> List[Dict[str, Any]]:
        if not target_dir.exists():
            print(f"[WARN] Target directory does not exist: {target_dir}")
            return []

        matches = []
        for rule in self.rules:
            print(f"[DEBUG] Using compiled rule: {rule}")
            for file in target_dir.rglob("*"):
                if file.is_file():
                    print(f"[DEBUG] Scanning file: {file}")
                    try:
                       result = rule.match(filepath=str(file))
                       for match in result:
                            matches.append({
                                "file": str(file.relative_to(target_dir)),
                                "rule": match.rule,
                                "tags": match.tags,
                                "meta": match.meta  # includes description, category, severity, etc.
                            })
                    except Exception as e:
                        print(f"[WARN] YARA failed on {file}: {e}")
        return matches

    def matches_to_dataframe(self, matches: List[Dict[str, Any]]) -> pd.DataFrame:
        rows = []
        for entry in matches:
            rows.append({
                "file": entry["file"],
                "rule": entry["rule"],
                "description": entry["meta"].get("description", ""),
                "severity": entry["meta"].get("severity", ""),
                "category": entry["meta"].get("category", ""),
                "confidence": entry["meta"].get("confidence", "")
            })
        return pd.DataFrame(rows)

