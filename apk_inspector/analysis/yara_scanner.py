import yara
import pkg_resources
import re
from pathlib import Path
from typing import List

from apk_inspector.reports.yara_match_model import YaraMatchModel
from apk_inspector.utils.yara_cleaner import clean_yara_match
from apk_inspector.utils.yara_utils import serialize_yara_strings
from apk_inspector.utils.logger import get_logger


class YaraScanner:
    def __init__(self, rules_dir: Path = Path("yara_rules")):
        self.rules_dir = rules_dir
        self.logger = get_logger()
        self.rules = self._compile_yara_rules()

        try:
            version = pkg_resources.get_distribution("yara-python").version
            self.logger.info(f"[YARA] Using yara-python version {version}")
        except Exception as ex:
            self.logger.warning(f"[YARA] Could not determine yara-python version: {ex}")

        # Allow scanning all common file types including dex, xml, js, etc.
        self.allowed_patterns = [
            re.compile(r".*\.(smali|dex|xml|json|js|txt|html|htm|ini|cfg|bin|sh)$", re.IGNORECASE),
            re.compile(r"^assets/"),
            re.compile(r"^res/"),
            re.compile(r"^lib/"),
            re.compile(r"^classes\d*\.dex$"),
        ]

        # Only skip large binaries and media
        self.skipped_exts = {
            ".png", ".jpg", ".jpeg", ".gif", ".ttf", ".otf", ".so", ".jar", ".zip", ".apk"
        }

    def _compile_yara_rules(self):
        if not self.rules_dir.exists():
            self.logger.warning(f"[YARA] Rules directory not found: {self.rules_dir}")
            return None

        rule_files = list(self.rules_dir.glob("*.yar"))
        if not rule_files:
            self.logger.warning(f"[YARA] No YARA rule files found in: {self.rules_dir}")
            return None

        try:
            rule_paths = {f.stem: str(f) for f in rule_files}
            compiled = yara.compile(filepaths=rule_paths)
            self.logger.info(f"[YARA] Compiled {len(rule_paths)} rules with namespaces.")
            return compiled
        except Exception as ex:
            self.logger.error(f"[YARA] Failed to compile YARA rules: {ex}")
            return None

    def scan_directory(
        self,
        target_dir: Path,
        timeout: int = 50,
        max_file_size: int = 5 * 1024 * 1024
    ) -> List[YaraMatchModel]:

        if not self.rules:
            self.logger.warning("[YARA] No compiled rules — skipping YARA scan.")
            return []

        if not target_dir.exists():
            self.logger.warning(f"[YARA] Target directory not found: {target_dir}")
            return []

        matches: List[YaraMatchModel] = []

        for file in target_dir.rglob("*"):
            if not file.is_file():
                continue

            rel_path = file.relative_to(target_dir).as_posix()
            ext = file.suffix.lower()

            # Skip big or irrelevant files
            if ext in self.skipped_exts:
                self.logger.debug(f"[YARA] Skipping {rel_path} by extension")
                continue
            if file.stat().st_size > max_file_size:
                self.logger.debug(f"[YARA] Skipping {rel_path} due to size > {max_file_size}")
                continue

            # Check if file matches allowed scan targets
            if not any(pattern.match(rel_path) for pattern in self.allowed_patterns):
                self.logger.debug(f"[YARA] Skipping {rel_path} — no pattern matched")
                continue

            try:
                self.logger.debug(f"[YARA] Scanning {rel_path}")
                results = self.rules.match(filepath=str(file), timeout=timeout)

                for m in results:
                    tags, meta = clean_yara_match(m)
                    try:
                        ystrs = serialize_yara_strings(m.strings)
                    except Exception as err:
                        self.logger.warning(f"[YARA] Failed serializing strings in {rel_path}/{m.rule}: {err}")
                        ystrs = []

                    matches.append(YaraMatchModel(
                        file=rel_path,
                        rule=m.rule,
                        tags=tags,
                        meta=meta,
                        strings=ystrs,
                        namespace=m.namespace
                    ))

            except yara.TimeoutError:
                self.logger.warning(f"[YARA] Timeout scanning {rel_path}")
            except Exception as ex:
                self.logger.warning(f"[YARA] Error scanning {rel_path}: {ex}")

        self.logger.info(f"[YARA] Collected {len(matches)} matches from {target_dir}")
        return matches
