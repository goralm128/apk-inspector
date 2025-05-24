import logging
import time
from pathlib import Path
from typing import List, Dict, Any

from apk_inspector.core.adb_tools import (
    wake_and_unlock, launch_app, force_stop_app,
    is_device_connected, check_device_compatibility
)
from apk_inspector.utils.frida_utils import trace_frida_events
from apk_inspector.utils.file_utils import is_private_ip, deduplicate_events
from apk_inspector.utils.hook_utils import discover_hooks
from apk_inspector.reports.report_saver import ReportSaver
from apk_inspector.reports.models import APKReportBuilder, YaraMatch


class APKInspector:
    def __init__(
        self,
        apk_path: Path,
        hooks_dir: Path,
        static_analyzer,
        yara_scanner,
        rule_engine,
        report_builder: APKReportBuilder,
        report_saver: ReportSaver,
        logger: logging.Logger
    ):
        self.apk_path = apk_path
        self.hooks_dir = hooks_dir
        self.static_analyzer = static_analyzer
        self.yara_scanner = yara_scanner
        self.rule_engine = rule_engine
        self.report_builder = report_builder
        self.report_saver = report_saver
        self.logger = logger

        self.hook_scripts = discover_hooks(hooks_dir)
        if not self.hook_scripts:
            raise FileNotFoundError(f"No hook scripts found in {hooks_dir}")

        self.static_analysis = {}
        self.yara_matches: List[YaraMatch] = []

    def _collect_hook_events(self, package_name: str) -> List[Dict[str, Any]]:
        all_events = []

        for hook_name, script in self.hook_scripts.items():
            self.logger.info(f"[{package_name}] Hook: {hook_name}")
            try:
                wake_and_unlock()
                launch_app(package_name)
                time.sleep(2)

                events = trace_frida_events(package_name, script, timeout=10)
                if hook_name == "network":
                    events = [
                        e for e in events
                        if not (ip := e.get("address", {}).get("ip")) or not is_private_ip(ip)
                    ]

                deduped = deduplicate_events(events)
                all_events.extend(deduped)

            except Exception as e:
                self.logger.exception(f"[{package_name}] Hook '{hook_name}' failed: {e}")
            finally:
                if is_device_connected():
                    force_stop_app(package_name)
                else:
                    self.logger.warning(f"Device disconnected before cleanup: {package_name}")

        return all_events

    def _run_hooks_and_evaluate(self) -> Dict[str, Any]:
        package_name = self.report_builder.package
        all_events = self._collect_hook_events(package_name)

        verdict_label, score_value, reason_list = self.rule_engine.evaluate(
            all_events,
            yara_hits=self.yara_matches
        )

        return {
            "events": all_events,
            "verdict": verdict_label,
            "score": score_value,
            "reasons": reason_list,
            "yara_matches": self.yara_matches,
            "static_analysis": self.static_analysis
        }

    def run(self):
        package_name = self.report_builder.package
        self.logger.info(f"[{package_name}] Running static analysis...")
        self.static_analysis = self.static_analyzer.analyze(self.apk_path)

        self.logger.info(f"[{package_name}] Running YARA scan...")
        yara_dicts = self.yara_scanner.scan_directory(self.report_saver.get_decompile_path(package_name))
        self.yara_matches = [YaraMatch(**match) for match in yara_dicts]
        self.report_saver.save_yara_csv(package_name, self.yara_matches)

        hook_result = self._run_hooks_and_evaluate()
        self.report_builder.merge_hook_result(hook_result)

        final_report = self.report_builder.build()
        self.report_saver.save_report(final_report)
        return final_report
