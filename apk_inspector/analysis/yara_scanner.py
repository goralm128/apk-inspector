import yara
import pkg_resources
import pandas as pd
from pathlib import Path
from typing import List
import re
from apk_inspector.reports.schemas import YaraMatchModel
from apk_inspector.utils.yara_cleaner import clean_yara_match
from apk_inspector.utils.yara_utils import convert_matches, serialize_yara_strings
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

    def _compile_yara_rules(self) -> List[yara.Rules]:
        if not self.rules_dir.exists():
            self.logger.warning(f"[YARA] Rules directory not found: {self.rules_dir}")
            return []

        compiled_rules = []
        for rule_file in self.rules_dir.glob("*.yar"):
            try:
                self.logger.info(f"[YARA] Compiling rule: {rule_file.name}")
                compiled_rules.append(yara.compile(filepath=str(rule_file)))
            except Exception as ex:
                self.logger.error(f"[YARA] Failed to compile {rule_file}: {ex}")
        return compiled_rules

    def scan_directory(self, target_dir: Path, max_file_size: int = 5 * 1024 * 1024) -> List[YaraMatchModel]:
        if not target_dir.exists():
            self.logger.warning(f"[YARA] Target directory does not exist: {target_dir}")
            return []

        skipped_dirs = {
            "lib", "res", "original", "assets", "META-INF",
            ".git", ".idea", ".gradle", "build"
        }

        skipped_exts = {
            ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
            ".mp3", ".mp4", ".ogg", ".wav", ".ttf", ".otf",
            ".so", ".apk", ".dex", ".jar", ".zip", ".bin", ".dat"
        }

        matches = []

        for rule in self.rules:
            for file in target_dir.rglob("*"):
                if not file.is_file():
                    continue

                relative_path = file.relative_to(target_dir)
                rel_path_str = str(relative_path).replace("\\", "/")  # Normalize on Windows

                if "smali/kotlin/" in rel_path_str:
                    self.logger.debug(f"YaraScanner: Skipping Kotlin stdlib file: {file}")
                    continue

                top_dir = relative_path.parts[0] if relative_path.parts else ""
                if top_dir in skipped_dirs:
                    self.logger.debug(f"YaraScanner: Skipping file in skipped dir '{top_dir}': {file}")
                    continue

                if file.suffix.lower() in skipped_exts:
                    self.logger.debug(f"YaraScanner: Skipping binary file: {file}")
                    continue

                if file.stat().st_size > max_file_size:
                    self.logger.debug(f"YaraScanner: Skipping large file: {file} ({file.stat().st_size} bytes)")
                    continue

                if not any(p.match(rel_path_str) for p in self.allowed_patterns):
                    self.logger.debug(f"YaraScanner: Skipping file not in allowed patterns: {rel_path_str}")
                    continue

                try:
                    with open(file, "rb") as f:
                        f.read()
                except Exception as ex:
                    self.logger.warning(f"YaraScanner: Skipping unreadable file: {file} ({ex})")
                    continue

                try:
                    result = rule.match(filepath=str(file))
                    for match in result:
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
                    self.logger.warning(f"YARA scan failed on {file}: {ex}")

        return matches