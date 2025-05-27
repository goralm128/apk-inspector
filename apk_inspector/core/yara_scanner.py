import yara
import pandas as pd
from pathlib import Path
from typing import List, Dict, Any
from apk_inspector.reports.models import YaraMatch
from apk_inspector.utils.yara_utils import clean_yara_match, serialize_yara_strings 
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

    def scan_directory(self, target_dir: Path, max_file_size: int = 5 * 1024 * 1024) -> List[YaraMatch]:
        if not target_dir.exists():
            logger.warning(f"Target directory does not exist: {target_dir}")
            return []

        # File extensions that are safe to skip (common binaries/media)
        skipped_exts = {".png", ".jpg", ".jpeg", ".gif", ".so", ".apk", ".mp3", ".mp4", ".ogg", ".webp"}

        # Top-level folders to skip in decompiled APKs
        skipped_dirs = {"lib", "res", "original"}
       
        matches = []

        for rule in self.rules:
            for file in target_dir.rglob("*"):
                if not file.is_file():
                    logger.debug(f"YaraScanner, Skipping non-file: {file}")
                    continue

                # Skip files in known uninteresting folders
                relative_path = file.relative_to(target_dir)
                top_dir = relative_path.parts[0] if relative_path.parts else ""
                if top_dir in skipped_dirs:
                    logger.debug(f"YaraScanner, Skipping file in skipped dir '{top_dir}': {file}")
                    continue

                # Skip files with certain extensions
                if file.suffix.lower() in skipped_exts:
                    logger.debug(f"YaraScanner, Skipping binary file: {file}")
                    continue

                # Skip files larger than the specified size
                if file.stat().st_size > max_file_size:
                    logger.debug(f"YaraScanner, Skipping large file: {file} ({file.stat().st_size} bytes)")
                    continue

                # Attempt to read the file to ensure it's not corrupted
                try:
                    with open(file, "rb") as f:
                        logger.debug(f"YaraScanner, Reading file: {file}")
                        f.read()
                except Exception as e:
                    logger.warning(f"Skipping unreadable file: {file} ({e})")
                    continue

                # Run YARA rules on the file
                try:
                    result = rule.match(filepath=str(file))
                    for match in result:
                        logger.debug(f"YaraScanner, Match found: {match.rule} in {file}")
                        # Clean the match to extract tags and meta information
                        tags, meta = clean_yara_match(match)
                        matches.append(YaraMatch(
                            file=str(file.relative_to(target_dir)),
                            rule=match.rule,
                            tags=tags,
                            meta=meta,
                            strings=serialize_yara_strings(match.strings),
                            namespace=match.namespace,
                        ))
                except Exception as e:
                    logger.warning(f"YARA scan failed on {file}: {e}")
        return matches

