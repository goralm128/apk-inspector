from datetime import datetime
import json
from pathlib import Path
from typing import List, Dict, Optional, Any
import pandas as pd
from apk_inspector.reports.schemas import YaraMatchModel
from apk_inspector.utils.logger import get_logger


class ReportSaver:
    """
    Handles saving, merging, clearing, and reading JSON reports for APK analysis.
    Automatically creates timestamped output folders and logging.
    """

    def __init__(self, run_dir: Path):
        self.run_dir = run_dir
        self.output_root = run_dir.parent
        self.timestamp = run_dir.name
        self.logger = get_logger()

        self.run_dir.mkdir(parents=True, exist_ok=True)

    def get_hook_result_path(self, package_name: str, hook_name: str) -> Path:
        return self.run_dir / f"{package_name}_{hook_name}.json"

    def _save_json(self, path: Path, data: Any, label: str) -> bool:
        try:
            # Validate before saving
            json_str = json.dumps(data, indent=2, ensure_ascii=False)  # triggers serialization issues
            json.loads(json_str)
            
            with path.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
            self.logger.info(f"{label} written to {path.resolve()}")
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to write {label}: {e}")
            try:
                if isinstance(data, list):
                    for idx, item in enumerate(data):
                        if not isinstance(item, dict):
                            self.logger.debug(f"[Debug] Unserializable item at index {idx}: {type(item)}")
                elif not isinstance(data, dict):
                    self.logger.debug(f"[Debug] Top-level data type: {type(data)}")
            except Exception as dbg:
                self.logger.debug(f"[Debug] Type inspection failed: {dbg}")
                    
            return False

    def save_report(self, report: Dict[str, Any]) -> Path:
        output_path = self.run_dir / f"{report['apk_metadata']['package_name']}.json"
        self._save_json(output_path, report, f"Report for {report['apk_metadata']['package_name']}")
        return output_path

    def save_yara_csv(self, package_name: str, matches: List[YaraMatchModel]) -> Optional[Path]:
        if not matches:
            self.logger.info(f"[~] No YARA matches to save for {package_name}.")
            return None

        from collections import defaultdict
        import pandas as pd

        # Group by (rule, category, file)
        grouped = defaultdict(lambda: {
            "package": package_name,
            "rule": "",
            "category": "",
            "severity": "",
            "confidence": "",
            "tags": "",
            "file": "",
            "match_count": 0
        })

        for match in matches:
            key = (match.rule, match.meta.get("category", "uncategorized"), match.file)
            group = grouped[key]

            group["rule"] = match.rule
            group["category"] = match.meta.get("category", "uncategorized")
            group["severity"] = match.meta.get("severity", "medium")
            group["confidence"] = match.meta.get("confidence", "")
            group["tags"] = ", ".join(match.tags)
            group["file"] = match.file
            group["match_count"] += 1

        rows = list(grouped.values())
        df = pd.DataFrame(rows)

        csv_path = self.run_dir / f"{package_name}_yara_summary.csv"
        try:
            df.to_csv(csv_path, index=False)
            self.logger.info(f"[✓] Saved enriched YARA summary CSV to: {csv_path.resolve()}")
            return csv_path
        except Exception as e:
            self.logger.error(f"[✗] Failed to save enriched YARA summary CSV: {e}")
            return None

    def save_yara_summary_json(self, results: List[Dict[str, Any]]):
        summary = {
            r.get("apk_metadata", {}).get("package_name", r.get("package", "unknown")):
            sorted([m.rule if hasattr(m, "rule") else "unknown" for m in r.get("yara_matches", [])])
            for r in results if "package" in r or "apk_metadata" in r
        }
        summary_path = self.run_dir / "yara_results.json"
        self._save_json(summary_path, summary, "YARA summary")

    def read_existing_results(self, file_path: Path) -> List[Dict[str, Any]]:
        if file_path.exists():
            try:
                with file_path.open("r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"[!] Failed to read existing results from {file_path}: {e}")
        return []

    def write_merged_results(self, file_path: Path, new_results: List[Dict[str, Any]]) -> None:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        existing = self.read_existing_results(file_path)
        merged = {r["package"]: r for r in existing}
        for res in new_results:
            merged[res["package"]] = res
        self._save_json(file_path, list(merged.values()), "Merged results")

    def clear_output_file(self, file_path: Path) -> None:
        if file_path.exists():
            try:
                file_path.unlink()
                self.logger.info(f"[~] Cleared existing results file: {file_path}")
            except Exception as e:
                self.logger.warning(f"[!] Unable to delete output file: {e}")
