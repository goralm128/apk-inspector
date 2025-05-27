
from apk_inspector.core.adb_tools import (
    wake_and_unlock, launch_app, force_stop_app,
    is_device_connected, check_device_compatibility
)
from apk_inspector.core.decompiler import decompile_apk
from apk_inspector.utils.hook_descovery import discover_hooks
from apk_inspector.utils.yara_utils import convert_matches
from apk_inspector.utils.logger import log_verdict_debug
from apk_inspector.analysis.dynamic.dynamic_analyzer import DynamicAnalyzer
from apk_inspector.reports.validators import validate_report_structure
from apk_inspector.reports.report_builder import APKReportBuilder
from apk_inspector.reports.models import Verdict

from typing import Dict, Any

class APKInspector:
    def __init__(self, apk_path, hooks_dir, static_analyzer, yara_scanner,
                 rule_engine, report_builder, report_saver, logger, timeout: int = 120):
        self.apk_path = apk_path
        self.hooks_dir = hooks_dir
        self.static_analyzer = static_analyzer
        self.yara_scanner = yara_scanner
        self.rule_engine = rule_engine
        self.report_builder = report_builder
        self.report_saver = report_saver
        self.logger = logger
        self.timeout = timeout

        self.hook_scripts = discover_hooks(hooks_dir)
        if not self.hook_scripts:
            raise FileNotFoundError(f"No hook scripts found in {hooks_dir}")

        self.static_analysis = {}
        self.yara_matches = []

    def run(self) -> Dict[str, Any]:
        package_name = self.report_builder.package

         # STEP 1: Resolve decompiled path
        decompiled_dir = self.report_saver.get_decompile_path(package_name, self.apk_path)

        # STEP 2: Validate decompiled output
        if not decompiled_dir.exists() or not any(decompiled_dir.iterdir()):
            self.logger.info(f"[{package_name}] Decompiling APK...")
            try:
                decompile_apk(self.apk_path, decompiled_dir)
            except Exception as e:
                self.logger.error(f"[{package_name}] Decompilation failed: {e}")
                return {
                    "package": package_name,
                    "verdict": "error",
                    "score": 0,
                    "events": [],
                    "yara_matches": [],
                    "static_analysis": {},
                    "error": f"Decompilation failed: {e}"
                }
        
        # STEP 3: Static analysis, yara scan, dynamic analysis
        static_info  = self.static_analyzer.analyze(self.apk_path, decompiled_dir)
        yara_matches = self.yara_scanner.scan_directory(decompiled_dir) # List[YaraMatch]
        dynamic_analyzer = DynamicAnalyzer(self.hook_scripts, self.logger)
        events = dynamic_analyzer.analyze(package_name)

        # Step 4: Evaluate Verdict
        verdict_label, score_value, reasons = self.rule_engine.evaluate(
            events,
            yara_hits=convert_matches(yara_matches), 
            static_info=static_info
        )
        verdict = Verdict(score=score_value, label=verdict_label, reasons=reasons)

        # Step 5: Log for debugging
        log_verdict_debug(
            logger=self.logger,
            package_name=package_name,
            score=score_value,
            verdict_label=verdict_label,
            reasons=reasons,
            events=events,
            yara_hits=self.yara_matches,
            static_info=static_info
        )

         # STEP 6: Construct report using builder
        self.report_builder.set_static_analysis(convert_matches(yara_matches), static_info)
        self.report_builder.merge_hook_result({
            "events": [e if isinstance(e, dict) else e.__dict__ for e in events],
            "verdict": verdict.label,
            "score": verdict.score,
            "reasons": verdict.reasons
        })

        return self.report_builder.build()