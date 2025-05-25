import yara
import pandas as pd
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger("YaraScanner")

class YaraScanner:
    def __init__(self, rules_dir: Path = Path("yara_rules")):
        self.rules_dir = rules_dir
        self.rules = self._compile_yara_rules()

    def _compile_yara_rules(self) -> List[yara.Rules]:
        if not self.rules_dir.exists():
            logger.warning(f"YARA rules directory not found: {self.rules_dir}")
            return []

        compiled_rules = []
        for rule_file in self.rules_dir.glob("*.yar"):
            try:
                logger.info(f"Compiling YARA rule: {rule_file.name}")
                compiled_rules.append(yara.compile(filepath=str(rule_file)))
            except Exception as e:
                logger.error(f"Failed to compile {rule_file}: {e}")
        return compiled_rules

    def scan_directory(self, target_dir: Path, max_file_size: int = 5 * 1024 * 1024) -> List[Dict[str, Any]]:
        if not target_dir.exists():
            logger.warning(f"Target directory does not exist: {target_dir}")
            return []

        skipped_exts = {".png", ".jpg", ".jpeg", ".gif", ".so", ".dex", ".apk", ".mp3", ".mp4", ".ogg", ".webp"}

        matches = []
        for rule in self.rules:
            for file in target_dir.rglob("*"):
                if not file.is_file():
                    continue
                if file.suffix.lower() in skipped_exts:
                    logger.debug(f"Skipping binary file: {file}")
                    continue
                if file.stat().st_size > max_file_size:
                    logger.debug(f"Skipping large file: {file} ({file.stat().st_size} bytes)")
                    continue

                try:
                    result = rule.match(filepath=str(file))
                    for match in result:
                        matches.append({
                            "file": str(file.relative_to(target_dir)),
                            "rule": match.rule,
                            "tags": match.tags,
                            "meta": match.meta,
                            "matched_strings": match.strings
                        })
                except Exception as e:
                    logger.warning(f"YARA scan failed on {file}: {e}")
        return matches

    def matches_to_dataframe(self, matches: List[Dict[str, Any]]) -> pd.DataFrame:
        rows = []
        for m in matches:
            rows.append({
                "file": m["file"],
                "rule": m["rule"],
                "description": m["meta"].get("description", ""),
                "severity": m["meta"].get("severity", ""),
                "category": m["meta"].get("category", ""),
                "confidence": m["meta"].get("confidence", ""),
                "tags": ", ".join(m["tags"]) if m["tags"] else ""
            })
        return pd.DataFrame(rows)
