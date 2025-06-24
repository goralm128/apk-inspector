import yara
import pkg_resources
import pandas as pd
from pathlib import Path
from typing import List
import re
from apk_inspector.reports.yara_match_model import YaraMatchModel
from apk_inspector.utils.yara_cleaner import clean_yara_match
from apk_inspector.utils.yara_utils import serialize_yara_strings
from apk_inspector.utils.logger import get_logger

class YaraScanner:
    def __init__(self, rules_dir: Path = Path("yara_rules")):
        self.rules_dir = rules_dir
        self.logger = get_logger()

        try:
            yara_version = pkg_resources.get_distribution("yara-python").version
            self.logger.info(f"[YARA] Using yara-python version {yara_version}")
        except Exception as ex:
            self.logger.warning(f"[YARA] Could not determine yara-python version: {ex}")

        self.rules = self._compile_yara_rules()

        # Define high-interest path patterns (Android malware best practices)
        self.allowed_patterns = [
            re.compile(r"^smali/(com|net|org)/[a-z0-9]{10,}/"),  # likely obfuscated root packages
            re.compile(r"^smali/.*?/Main.*?\.smali$"),  # entry point classes
            re.compile(r"^smali/.*?/MyService.*?\.smali$"),  # suspicious services
            re.compile(r"^smali/.*?/(Overlay|Accessibility|AccessibilityNode).*?\.smali$"),  # abuse-prone features
            re.compile(r"^smali/okhttp3/ConnectionSpec\.smali$"),  # known abuse target
            re.compile(r"^smali/.*?/x(\.smali)?$"),  # short obfuscated classes
        ]

    def _compile_yara_rules(self) -> yara.Rules | None:
        if not self.rules_dir.exists():
            self.logger.warning(f"[YARA] Rules directory not found: {self.rules_dir}")
            return None

        sources = {
            rule_file.stem: str(rule_file)
            for rule_file in self.rules_dir.glob("*.yar")
        }

        try:
            compiled = yara.compile(filepaths=sources)
            self.logger.info(f"[YARA] Compiled {len(sources)} YARA rule files with namespaces.")
            return compiled
        except Exception as ex:
            self.logger.error(f"[YARA] Failed to compile rules with namespaces: {ex}")
            return None


    def scan_directory(self, target_dir: Path, max_file_size: int = 5 * 1024 * 1024) -> List[YaraMatchModel]:
        if not self.rules:
            self.logger.warning("[YARA] No compiled rules available. Skipping scan.")
            return []

        if not target_dir.exists():
            self.logger.warning(f"[YARA] Target directory does not exist: {target_dir}")
            return []

        matches = []
        skipped_dirs = {"lib", "res", "original", "assets", "META-INF", ".git", ".idea", ".gradle", "build"}
        skipped_exts = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".mp3", ".mp4", ".ogg", ".wav", ".ttf", ".otf",
                        ".so", ".apk", ".dex", ".jar", ".zip", ".bin", ".dat"}

        files_to_scan = []
        for file in target_dir.rglob("*"):
            if not file.is_file():
                continue

            rel_path = file.relative_to(target_dir).as_posix()

            if (
                "smali/kotlin/" in rel_path or
                file.suffix.lower() in skipped_exts or
                file.stat().st_size > max_file_size or
                (file.parts[0] in skipped_dirs if file.parts else False) or
                not any(p.match(rel_path) for p in self.allowed_patterns)
            ):
                continue

            files_to_scan.append(file)

        if not files_to_scan:
            self.logger.info(f"[YARA] No eligible files to scan in: {target_dir}")
            return []

        for file in files_to_scan:
            try:
                results = self.rules.match(filepath=str(file), timeout=10)
                for match in results:
                    tags, meta = clean_yara_match(match)
                    try:
                        serialized_strings = serialize_yara_strings(match.strings)
                    except Exception as string_err:
                        self.logger.warning(
                            f"[YARA] Failed to serialize match.strings in {file} ({match.rule}): {string_err}"
                        )
                        serialized_strings = []

                    matches.append(YaraMatchModel(
                        file=str(file.relative_to(target_dir)),
                        rule=match.rule,
                        tags=tags,
                        meta=meta,
                        strings=serialized_strings,
                        namespace=str(match.namespace),
                    ))
            except Exception as ex:
                self.logger.warning(f"[YARA] Scan failed on {file}: {ex}")

        return matches
