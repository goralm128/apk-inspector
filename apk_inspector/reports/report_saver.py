from datetime import datetime
import json
from pathlib import Path
from typing import List, Dict, Optional, Any
import pandas as pd
from apk_inspector.utils.logger import setup_logger
from apk_inspector.reports.models import YaraMatch


class ReportSaver:
    """
    Handles saving, merging, clearing, and reading JSON reports for APK analysis.
    Automatically creates timestamped output folders and logging.
    """

    def __init__(self, output_root: Path = Path("output"), logger: Optional[Any] = None):
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.output_root = output_root
        self.run_dir = output_root / self.timestamp
        self.run_dir.mkdir(parents=True, exist_ok=True)

        self.log_path = self.run_dir / "full.log"
        self._logger = logger or setup_logger(verbose=True, log_path=self.log_path)

    @property
    def logger(self):
        return self._logger

    def get_decompile_path(self, package_name: str) -> Path:
        path = self.run_dir / "decompiled" / package_name
        path.mkdir(parents=True, exist_ok=True)
        return path

    def get_hook_result_path(self, package_name: str, hook_name: str) -> Path:
        return self.run_dir / f"{package_name}_{hook_name}.json"

    def _save_json(self, path: Path, data: Any, label: str) -> bool:
        try:
            # Validate before saving
            json_str = json.dumps(data, indent=2, ensure_ascii=False)
            json.loads(json_str)  # throws if not valid
            with path.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.logger.info(f"[\u2713] {label} written to {path.resolve()}")
            return True
        except Exception as e:
            self.logger.error(f"[\u2717] Failed to write {label}: {e}")
            return False

    def save_report(self, report: Dict[str, Any]) -> Path:
        output_path = self.run_dir / f"{report['apk_metadata']['package_name']}.json"
        self._save_json(output_path, report, f"Report for {report['apk_metadata']['package_name']}")
        return output_path

    def save_yara_csv(self, package_name: str, matches: List[YaraMatch]) -> Optional[Path]:
        if not matches:
            self.logger.info(f"[~] No YARA matches to save for {package_name}.")
            return None

        rows = [
            {"file": match.file, "rule": rule}
            for match in matches
            for rule in match.matched_rules
        ]
        df = pd.DataFrame(rows)
        csv_path = self.run_dir / f"{package_name}_yara_matches.csv"
        try:
            df.to_csv(csv_path, index=False)
            self.logger.info(f"[\u2713] Saved YARA match CSV for {package_name} to {csv_path.resolve()}")
            return csv_path
        except Exception as e:
            self.logger.error(f"[\u2717] Failed to write YARA CSV for {package_name}: {e}")
            return None

    def save_yara_summary_json(self, results: List[Dict[str, Any]]):
        summary = {
            r["package"]: [m.get("matched_rules", []) for m in r.get("yara_matches", [])]
            for r in results if "package" in r
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
