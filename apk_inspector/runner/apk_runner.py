from pathlib import Path
from typing import List
import json
from apk_inspector.reports.summary_builder import SummaryBuilder
from apk_inspector.reports.report_saver import ReportSaver
from apk_inspector.core.apk_manager import APKManager
from apk_inspector.factories.inspector_factory import create_apk_inspector
from functools import partial
from apk_inspector.core.analyze_entrypoint import analyze_apk_entrypoint


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
        results = [
            analyze_apk_entrypoint(
                apk_path,
                hooks_dir=self.hooks_dir,
                report_saver=self.report_saver,  # shared instance
                verbose=True
            )
            for apk_path in self.apk_paths
        ]
        # Filter out invalid results
        valid_results = []
        for r in results:
            if isinstance(r, dict) and "apk_metadata" in r:
                valid_results.append(r)
            else:
                self.logger.warning("[!] Skipping invalid result: %s", str(r)[:200])  # Avoids printing huge blobs  
        self._save_results(valid_results)

    def _run_parallel(self):
        from multiprocessing import get_context
        func = partial(
            analyze_apk_entrypoint,
            hooks_dir=self.hooks_dir,
            output_dir=self.report_saver.output_root,
            verbose=True
        )

        with get_context("spawn").Pool(processes=min(4, len(self.apk_paths))) as pool:
            results = pool.map(func, self.apk_paths)

        valid_results = []
        for r in results:
            if isinstance(r, dict) and "apk_metadata" in r:
                valid_results.append(r)
            else:
                self.logger.warning("[!] Skipping invalid result: %s", str(r)[:200])

        self._save_results(valid_results)

    # Not in use, but kept for reference
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
            summary = SummaryBuilder(report).build_summary()
            summary_path = self.report_saver.run_dir / f"{summary['apk_package']}_summary.json"
            self.report_saver._save_json(summary_path, summary, f"Summary for {summary['apk_package']}")
            self.report_saver.save_report(report)
            return report

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
        if not results:
            self.logger.warning("[!] No valid results to save.")
            return

        # Save full combined JSON report
        combined_report = self.report_saver.run_dir / "combined_report.json"
        with combined_report.open("w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        self.logger.info(f"[✓] Combined JSON report saved to: {combined_report.resolve()}")

        # Save YARA match summary (flattened)
        yara_summary = {
            r.get("apk_metadata", {}).get("package_name", r.get("package", "unknown")): 
            [m.get("rule") for m in r.get("yara_matches", [])]
            for r in results
        }
        yara_summary_path = self.report_saver.run_dir / "yara_results.json"
        with yara_summary_path.open("w", encoding="utf-8") as f:
            json.dump(yara_summary, f, indent=2, ensure_ascii=False)
        self.logger.info(f"[✓] YARA summary saved to: {yara_summary_path.resolve()}")

        # Save summarized metadata
        summaries = SummaryBuilder.build_combined_summaries(results)
        # Save combined summary JSON
        if not summaries:
            self.logger.warning("[!] No valid summaries to save.")
            return
        summary_json = self.report_saver.run_dir / "combined_summary.json"
        with summary_json.open("w", encoding="utf-8") as f:
            json.dump(summaries, f, indent=2, ensure_ascii=False)
        self.logger.info(f"[✓] Combined summary saved to: {summary_json.resolve()}")
        # Save CSV summary
        summary_csv = self.report_saver.run_dir / "combined_summary.csv"
        SummaryBuilder.export_csv(summaries, summary_csv)
        self.logger.info(f"[✓] CSV summary saved to: {summary_csv.resolve()}")


    # Important: ReportSaver is created once per batch run
    # to ensure that all reports are saved under the same run_dir.
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
