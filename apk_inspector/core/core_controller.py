
from apk_inspector.core.adb_tools import (
    wake_and_unlock, launch_app, force_stop_app,
    is_device_connected, check_device_compatibility
)
from apk_inspector.utils.hook_descovery import discover_hooks
from apk_inspector.reports.models import YaraMatch
from apk_inspector.analysis.dynamic.dynamic_analyzer import DynamicAnalyzer
from apk_inspector.reports.validators import validate_report_structure

class APKInspector:
    def __init__(self, apk_path, hooks_dir, static_analyzer, yara_scanner, rule_engine,
                 report_builder, report_saver, logger):
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
        self.yara_matches = []

    def run(self):
        package_name = self.report_builder.package
        self.logger.info(f"[{package_name}] Running static analysis...")
        static = self.static_analyzer.analyze(self.apk_path)
        self.static_analysis = static

        self.logger.info(f"[{package_name}] Running YARA scan...")
        yara_raw = self.yara_scanner.scan_directory(self.report_saver.get_decompile_path(package_name))
        self.yara_matches = [YaraMatch(**match) for match in yara_raw]
        self.report_saver.save_yara_csv(package_name, self.yara_matches)

        self.logger.info(f"[{package_name}] Running dynamic analysis...")
        dynamic_analyzer = DynamicAnalyzer(self.hook_scripts, self.logger)
        all_events = dynamic_analyzer.analyze(package_name)

        verdict_label, score_value, reasons = self.rule_engine.evaluate(
            all_events, yara_hits=self.yara_matches, static_info=static
        )

        self.report_builder.merge_hook_result({
            "events": all_events,
            "verdict": verdict_label,
            "score": score_value,
            "reasons": reasons
        })

        self.report_builder.set_static(self.yara_matches, static)
        final_report = self.report_builder.build()
        # Validate before saving
        if validate_report_structure(final_report):
            self.report_saver.save_report(final_report)
        else:
            self.logger.error(f"[!] Report validation failed for {package_name}")
        return final_report


