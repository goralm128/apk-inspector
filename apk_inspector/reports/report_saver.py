from datetime import datetime
import json
from pathlib import Path
from typing import List, Dict, Optional, Any
from collections import defaultdict
import pandas as pd
from apk_inspector.reports.yara_match_model import YaraMatchModel
from apk_inspector.utils.logger import get_logger
import re


def make_json_safe(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_safe(v) for v in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, Path):
        return str(obj)
    return obj


def sanitize_filename(name: str) -> str:
    return re.sub(r"[^\w\-_.]", "_", name)


class ReportSaver:
    def __init__(self, run_dir: Path):
        self.run_dir = run_dir
        self.output_root = run_dir.parent
        self.timestamp = run_dir.name
        self.logger = get_logger()
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def get_apk_dir(self, package_name: str) -> Path:
        safe_name = sanitize_filename(package_name)
        apk_dir = self.run_dir / safe_name
        apk_dir.mkdir(parents=True, exist_ok=True)
        return apk_dir

    def _save_json(self, path: Path, data: Any, label: str) -> bool:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8") as f:
                json.dump(make_json_safe(data), f, indent=2, ensure_ascii=False)
            self.logger.info(f"[✓] {label} written to {path.resolve()}")
            return True
        except Exception as ex:
            self.logger.error(f"[✗] Failed to write {label}: {ex}")
            return False

    def save_report(self, report: Dict[str, Any]) -> Path:
        pkg = report["apk_metadata"]["package_name"]
        apk_dir = self.get_apk_dir(pkg)
        path = apk_dir / "report.json"
        self._save_json(path, report, f"Report for {pkg}")
        return path

    def save_yara_csv(self, package_name: str, matches: List[YaraMatchModel]) -> Optional[Path]:
        if not matches:
            self.logger.info(f"[~] No YARA matches to save for {package_name}.")
            return None

        grouped = defaultdict(lambda: {
            "package": package_name, "rule": "", "category": "",
            "severity": "", "confidence": "", "tags": "", "file": "", "match_count": 0
        })

        for m in matches:
            key = (m.rule, m.meta.get("category", "uncategorized"), m.file)
            grp = grouped[key]
            grp.update({
                "rule": m.rule,
                "category": m.meta.get("category", "uncategorized"),
                "severity": m.meta.get("severity", "medium"),
                "confidence": m.meta.get("confidence", ""),
                "tags": ", ".join(m.tags),
                "file": m.file,
            })
            grp["match_count"] += 1

        df = pd.DataFrame(list(grouped.values()))
        path = self.get_apk_dir(package_name) / "yara_summary.csv"
        try:
            df.to_csv(path, index=False)
            self.logger.info(f"[✓] Saved YARA CSV: {path.resolve()}")
            return path
        except Exception as ex:
            self.logger.error(f"[✗] Failed to save YARA CSV: {ex}")
            return None
