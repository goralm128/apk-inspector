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

        try:
            version = pkg_resources.get_distribution("yara-python").version
            self.logger.info(f"[YARA] Using yara-python version {version}")
        except Exception as ex:
            self.logger.warning(f"[YARA] Could not determine yara-python version: {ex}")

        self.rules = self._compile_yara_rules()

        # Expanded file pattern set
        self.allowed_patterns = [
            re.compile(r"^smali/"),
            re.compile(r"^smali_classes2/"),
            re.compile(r"^assets/scripts/"),
            re.compile(r"^assets/"),
        ]

    def _compile_yara_rules(self):
        if not self.rules_dir.exists():
            self.logger.warning(f"[YARA] Rules directory not found: {self.rules_dir}")
            return None
        paths = {f.stem: str(f) for f in self.rules_dir.glob("*.yar")}
        try:
            compiled = yara.compile(filepaths=paths)
            self.logger.info(f"[YARA] Compiled {len(paths)} rules with namespaces.")
            return compiled
        except Exception as ex:
            self.logger.error(f"[YARA] Failed to compile rules: {ex}")
            return None

    def scan_directory(self, target_dir: Path, timeout: int = 50, max_file_size: int = 5*1024*1024) -> List[YaraMatchModel]:
        if not self.rules:
            self.logger.warning("[YARA] No compiled rules — skipping.")
            return []
        if not target_dir.exists():
            self.logger.warning(f"[YARA] Target directory not found: {target_dir}")
            return []

        matches = []
        skipped_exts = {".png", ".jpg", ".so", ".ttf", ".jar", ".zip", ".apk", ".dex", ".bin"}

        for file in target_dir.rglob("*"):
            if not file.is_file():
                continue

            rel = file.relative_to(target_dir).as_posix()
            ext = file.suffix.lower()

            if ext in skipped_exts or file.stat().st_size > max_file_size:
                continue

            if not any(p.match(rel) for p in self.allowed_patterns):
                continue

            try:
                self.logger.debug(f"[YARA] Scanning {rel}")
                results = self.rules.match(filepath=str(file), timeout=timeout)

                for m in results:
                    tags, meta = clean_yara_match(m)
                    try:
                        ystrs = serialize_yara_strings(m.strings)
                    except Exception as strerr:
                        self.logger.warning(f"[YARA] Failed serializing strings in {rel}/{m.rule}: {strerr}")
                        ystrs = []

                    matches.append(YaraMatchModel(
                        file=rel,
                        rule=m.rule,
                        tags=tags,
                        meta=meta,
                        strings=ystrs,
                        namespace=m.namespace
                    ))

            except yara.TimeoutError:
                self.logger.warning(f"[YARA] Timeout scanning {rel}")
            except Exception as ex:
                self.logger.warning(f"[YARA] Error scanning {rel}: {ex}")

        self.logger.info(f"[YARA] Collected {len(matches)} matches from {target_dir}")
        return matches
