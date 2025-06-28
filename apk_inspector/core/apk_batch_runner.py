
import time
from pathlib import Path
from typing import List, Dict, Any, Tuple
from functools import partial
from multiprocessing import get_context

from apk_inspector.reports.report_manager import ReportManager
from apk_inspector.reports.models import ApkSummary
from apk_inspector.analysis.apk_analysis import analyze_apk_and_summarize
from apk_inspector.utils.logger import get_logger
from apk_inspector.utils.batch_helpers import safe_analyze_parallel


class APKBatchRunner:
    """
    Orchestrates batch APK analysis and delegates report saving to ReportManager.
    """
    
    def __init__(
        self,
        apk_paths: List[Path],
        hooks_dir: Path,
        report_manager: ReportManager,
        timeout: int = 30,
        include_private: bool = False,
        parallel: bool = False
    ):
        self.apk_paths = apk_paths
        self.hooks_dir = hooks_dir
        self.timeout = timeout
        self.include_private = include_private
        self.parallel = parallel
        
        self.report_manager = report_manager
        self.report_saver = report_manager.report_saver
        self.logger = get_logger()

    def run(self):
        """
        Runs the batch APK analysis in serial or parallel mode and stores valid results.
        """
        mode = "parallel" if self.parallel else "serial"
        self.logger.info(f"[*] Running APK analysis in {mode} mode...")

        results = self._run_parallel() if self.parallel else self._run_serial()
        valid_results = self._filter_valid_results(results)
        
        self.report_manager.store_analysis_results(valid_results)
      
        self.logger.info(f"[✓] Analysis complete: {len(valid_results)}/{len(self.apk_paths)} valid results stored.")

    def _run_serial(self) -> List[Tuple[Dict[str, Any], ApkSummary]]:
        results = []
        for apk_path in self.apk_paths:
            try:
                start_time = time.perf_counter()
                full_report, summary = analyze_apk_and_summarize(
                    apk_path,
                    hooks_dir=self.hooks_dir,
                    run_dir=self.report_manager.run_dir,
                    verbose=True,
                    timeout=self.timeout
                )
                elapsed_time = time.perf_counter() - start_time
                print(f"[✓] Analysis completed for {apk_path.name} in {elapsed_time:.2f} seconds.")
                self.logger.info(f"[✓] Analysis completed for {apk_path.name} in {elapsed_time:.2f} seconds.")
                results.append((full_report, summary))
                # Force GC
                # import gc
                # gc.collect()
                             
            except Exception as ex:
                self.logger.error(f"[✗] Analysis failed for {apk_path.name}: {ex}")
                
        return results        

    def _run_parallel(self) -> List[Tuple[Dict[str, Any], ApkSummary]]:

        safe_func = partial(
            safe_analyze_parallel,
            hooks_dir=self.hooks_dir,
            run_dir=self.report_manager.run_dir,
            timeout=self.timeout
        )

        with get_context("spawn").Pool(processes=min(4, len(self.apk_paths))) as pool:
            results = pool.map(safe_func, self.apk_paths)

        return results
    
    def _filter_valid_results(
        self, results: List[Tuple[Dict[str, Any], ApkSummary]]
    ) -> List[Tuple[Dict[str, Any], ApkSummary]]:
        valid = []
        for full_report, summary in results:
            if isinstance(full_report, dict) and "apk_metadata" in full_report:
                valid.append((full_report, summary))
            else:
                pkg = full_report.get("package", "unknown")
                self.logger.warning(f"[!] Skipping result for {pkg}: Missing apk_metadata.")
        return valid
    