from multiprocessing import Pool
from pathlib import Path
from typing import List
import json
from dataclasses import asdict

from apk_inspector.reports.report_saver import ReportSaver
from apk_inspector.core.apk_manager import APKManager
from apk_inspector.factories.inspector_factory import create_apk_inspector


class APKBatchRunner:
    def __init__(
        self,
        apk_paths: List[Path],
        hooks_dir: Path,
        report_saver: ReportSaver,
        timeout: int = 10,
        include_private: bool = False,
        parallel: bool = False
    ):
        self.apk_paths = apk_paths
        self.hooks_dir = hooks_dir
        self.report_saver = report_saver
        self.logger = report_saver.logger
        self.timeout = timeout
        self.include_private = include_private
        self.parallel = parallel

    def run(self):
        if self.parallel:
            self._run_parallel()
        else:
            self._run_serial()

    def _run_serial(self):
        results = [self._analyze_apk(apk_path) for apk_path in self.apk_paths]
        self._save_results(results)

    def _run_parallel(self):
        with Pool(processes=min(4, len(self.apk_paths))) as pool:
            results = pool.map(self._analyze_apk, self.apk_paths)
        self._save_results(results)

    def _analyze_apk(self, apk_path: Path) -> dict:
        apk_manager = APKManager(logger=self.logger)
        pkg_name = apk_manager.get_package_name(apk_path)

        if not pkg_name:
            self.logger.error(f"[{apk_path.name}] Could not determine package name.")
            return {
                "package": apk_path.stem,
                "verdict": "error",
                "score": 0,
                "events": [],
                "yara_matches": [],
                "static_analysis": {}
            }

        try:
            inspector = create_apk_inspector(
                apk_path=apk_path,
                hooks_dir=self.hooks_dir,
                output_dir=self.report_saver.output_root,  # not run_dir
                verbose=True  # or pass self.logger.level == logging.DEBUG
            )
            report = inspector.run()
            self.report_saver.save_report(report)
            return asdict(report)

        except Exception as e:
            self.logger.error(f"[{apk_path.name}] Analysis failed: {e}")
            return {
                "package": pkg_name,
                "verdict": "error",
                "score": 0,
                "events": [],
                "yara_matches": [],
                "static_analysis": {}
            }

    def _save_results(self, results: List[dict]):
        combined_report = self.report_saver.run_dir / "combined_report.json"
        with combined_report.open("w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        self.logger.info(f"[✓] Combined JSON report saved to: {combined_report.resolve()}")

        yara_summary = {
            r["package"]: [match.get("matched_rules", []) for match in r.get("yara_matches", [])]
            for r in results if "package" in r
        }
        yara_summary_path = self.report_saver.run_dir / "yara_results.json"
        with yara_summary_path.open("w", encoding="utf-8") as f:
            json.dump(yara_summary, f, indent=2, ensure_ascii=False)
        self.logger.info(f"[✓] YARA summary saved to: {yara_summary_path.resolve()}")


def run_all_apks(args, parallel: bool = False):
    report_saver = ReportSaver(output_root=args.output_dir)
    apk_paths = sorted(Path(args.apk_dir).glob("*.apk"))

    if not apk_paths:
        report_saver.logger.warning(f"[!] No APKs found in directory: {args.apk_dir}")
        return

    runner = APKBatchRunner(
        apk_paths=apk_paths,
        hooks_dir=args.hooks_dir,
        report_saver=report_saver,
        timeout=args.timeout,
        include_private=args.include_private,
        parallel=parallel
    )
    runner.run()
