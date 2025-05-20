import yara
from pathlib import Path

def compile_yara_rules(rules_dir: Path) -> list:
    return [
        yara.compile(filepath=str(rule_file))
        for rule_file in rules_dir.glob("*.yar")
    ]

def match_files_in_dir(rules, target_dir: Path) -> list:
    matches = []
    for rule in rules:
        print(f"[DEBUG] Using rule: {rule}")
        for file in target_dir.rglob("*"):
            if file.is_file():
                print(f"[DEBUG] Scanning file: {file}")
                try:
                    result = rule.match(filepath=str(file))
                    if result:
                        print(f"[MATCH] {file.name} → {result}")
                        matches.append({
                            "file": str(file.relative_to(target_dir)),
                            "matches": [str(r) for r in result]
                        })
                except Exception as e:
                    print(f"[WARN] YARA failed on {file}: {e}")
    return matches

def scan_with_yara(path_to_scan: Path, rules_dir: Path = Path("yara_rules")) -> list:
    if not rules_dir.exists():
        print(f"[WARN] Rules directory not found: {rules_dir}")
        return []
    
    rules = compile_yara_rules(rules_dir)
    return match_files_in_dir(rules, path_to_scan)

# Optional: Pandas export
import pandas as pd

def yara_matches_to_dataframe(yara_matches: list) -> pd.DataFrame:
    rows = []
    for entry in yara_matches:
        for rule in entry["matches"]:
            rows.append({"file": entry["file"], "rule": rule})
    return pd.DataFrame(rows)
