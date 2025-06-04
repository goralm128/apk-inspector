from typing import Dict, Any, Tuple
from pathlib import Path
from apk_inspector.analysis.apk_analysis import analyze_apk_and_summarize
from apk_inspector.reports.models import ApkSummary
from apk_inspector.utils.report_utils import build_error_report

def safe_analyze_parallel(
        apk_path: Path,
        hooks_dir: Path,
        run_dir: Path,
        timeout: int
    ) -> Tuple[Dict[str, Any], ApkSummary]:
        try:
            report, summary = analyze_apk_and_summarize(
                apk_path,
                hooks_dir=hooks_dir,
                run_dir=run_dir,
                verbose=True,
                timeout=timeout
            )
            return report, summary
        except Exception as e:
            return build_error_report(apk_path, str(e)), ApkSummary.from_dict({"error": str(e)})