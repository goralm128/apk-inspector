
from typing import List, Dict, Any, Tuple
from pathlib import Path

from apk_inspector.reports.models import ApkSummary
from apk_inspector.reports.report_saver import ReportSaver
from apk_inspector.utils.logger import get_logger
from apk_inspector.visual.per_apk_dashboard import generate_index_page

from apk_inspector.reports.full_report_aggregator import FullReportAggregator
from apk_inspector.reports.visualization_generator import VisualizationGenerator


class ReportManager:
    
    def __init__(self, report_saver: ReportSaver):
        self.report_saver = report_saver
        self.logger = get_logger()
        self.run_dir = report_saver.run_dir
        self.full_aggregator = FullReportAggregator(report_saver)
        self.visualizer = VisualizationGenerator(report_saver, self.run_dir)

    def store_analysis_results(self, results: List[Tuple[Dict[str, Any], ApkSummary]]) -> None:
        """
        Store the analysis results in the run directory.        
        :param results: List of tuples containing the full report and summary for each APK.
        """
        if not results:
            self.logger.warning("[!] No results to store.")
            return

        full_reports = [r[0] for r in results]
        summaries = [r[1] for r in results]

        self.full_aggregator.save_combined_json(full_reports)
        self.full_aggregator.save_summary_outputs(summaries)

        for report, summary in zip(full_reports, summaries):
            pkg = summary.apk_package or "unknown"
            apk_dir = self.report_saver.get_apk_dir(pkg)
            self.report_saver.save_report(report)
            self.visualizer.save_per_apk_visuals(report, summary, apk_dir)

        self.visualizer.generate_heatmap(full_reports)
        generate_index_page(summaries, self.run_dir)
