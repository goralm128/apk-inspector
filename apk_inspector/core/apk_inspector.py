from pathlib import Path
from typing import Dict, Any, List
from pathlib import Path
import yaml
from datetime import datetime, timezone
from apk_inspector.analysis.dynamic.hook_descovery import discover_hooks
from apk_inspector.analysis.dynamic.dynamic_analyzer import DynamicAnalyzer
from apk_inspector.analysis.static.static_analyzer import StaticAnalyzer
from apk_inspector.analysis.tag_inferencer import TagInferencer
from apk_inspector.analysis.yara_scanner import YaraScanner
from apk_inspector.rules.rule_engine import RuleEngine
from apk_inspector.reports.report_builder import APKReportBuilder
from apk_inspector.core.workspace_manager import WorkspaceManager
from apk_inspector.utils.logger import get_logger
from apk_inspector.core.decompiler import decompile_apk
from apk_inspector.reports.models import Verdict
from apk_inspector.utils.yara_utils import ensure_yara_models
from apk_inspector.utils.logger import log_verdict_debug
from apk_inspector.config.defaults import CONFIG_RULES_DIR


class APKInspector:
    def __init__(
        self,
        apk_path: Path,
        hooks_dir: Path,
        static_analyzer: StaticAnalyzer,
        yara_scanner: YaraScanner,
        rule_engine: RuleEngine,
        report_builder: APKReportBuilder,
        workspace: WorkspaceManager,
        run_dir: Path,
        logger=None,
        timeout: int = 120
    ):
        self.apk_path = apk_path
        self.hooks_dir = hooks_dir
        self.static_analyzer = static_analyzer
        self.yara_scanner = yara_scanner
        self.rule_engine = rule_engine
        self.report_builder = report_builder
        self.workspace = workspace
        self.run_dir = run_dir
        self.logger = logger or get_logger()
        self.timeout = timeout

        if not self.hooks_dir.exists():
            raise FileNotFoundError(f"Hook directory not found: {self.hooks_dir}")

        hook_scripts = discover_hooks(self.hooks_dir, logger)
        if not hook_scripts:
            logger.error(f"[✗] No valid Frida hook scripts found in: {hooks_dir.resolve()}")
            raise RuntimeError(f"No Frida hook scripts found in: {self.hooks_dir}")

    def run(self) -> Dict[str, Any]:
        self.report_builder.reset()
        package_name = self.report_builder.package
        base_report = {
            "apk_metadata": {
                "package_name": package_name,
                "source_apk": str(self.apk_path)
            }
        }

        try:
            self._ensure_decompiled(package_name)
            static_info = self._perform_static_analysis(package_name)

            raw_yara_matches = self._run_yara_scan(package_name)
            if raw_yara_matches is None:
                raw_yara_matches = []
            yara_models = ensure_yara_models(raw_yara_matches)
            self.logger.info(f"[{package_name}] {len(yara_models)} validated YARA matches found.")
            
            # Load tag_rules from YAML file
            tag_rules_path = CONFIG_RULES_DIR / "tag_rules.yaml"
            try:
                with tag_rules_path.open("r", encoding="utf-8") as f:
                    tag_rules = yaml.safe_load(f) or {}
                self.logger.info(f"[{package_name}] Loaded {len(tag_rules)} tag rule groups from {tag_rules_path.name}")
            except Exception as e:
                self.logger.warning(f"[{package_name}] Failed to load tag rules from {tag_rules_path}: {e}")
                tag_rules = {}
            
            tag_inferencer = TagInferencer(tag_rules)
            
            # Build APK metadata once per run
            apk_metadata = {
                "package_name": package_name,
                "apk_name": self.apk_path.name,
                "apk_path": str(self.apk_path),               
            }

            dynamic_analyzer = DynamicAnalyzer(
                hooks_dir=self.hooks_dir,
                logger=self.logger,
                rule_engine=self.rule_engine,
                tag_inferencer=tag_inferencer,
                run_dir=self.run_dir,
                timeout=self.timeout
            )
            
            hook_metadata_map = dynamic_analyzer.hook_metadata_map
            self.report_builder.set_hook_metadata(hook_metadata_map)
            
            dyn_res = dynamic_analyzer.analyze(package_name, apk_metadata=apk_metadata)
            events = dyn_res.get("events", [])
            hook_counts = dyn_res.get("hook_event_counts", {})
            self.logger.info(f"[{package_name}] Dynamic analysis collected {len(events)} events.")
            
            verdict = self.rule_engine.evaluate(
                events=events,
                yara_hits=[m.model_dump() for m in yara_models],
                static_info=static_info,
                hook_coverage=hook_counts,
            )

            self._log_verdict(package_name, verdict, events, raw_yara_matches, static_info)

            self.report_builder.set_static_analysis(yara_models, static_info)
            
            self.report_builder.merge_hook_result({
               "events": events,
                "hook_event_counts": hook_counts,
                "verdict": verdict
            })

            final_report = self.report_builder.build()
            return {**base_report, **final_report}

        except Exception as ex:
            self.logger.exception(f"[{package_name}] Fatal error during inspection: {ex}")
            return self._error_result(package_name, base_report, str(ex))

    def _ensure_decompiled(self, package_name: str):
        decompiled_dir = self.workspace.get_decompile_path(package_name)

        if not decompiled_dir.exists() or not any(decompiled_dir.iterdir()):
            self.logger.info(f"[{package_name}] Decompiled folder missing or empty. Starting decompilation...")
            self.workspace.create_decompile_dir(package_name)
            decompile_apk(self.apk_path, decompiled_dir)
        else:
            self.logger.info(f"[{package_name}] Reusing existing decompiled code.")

    def _perform_static_analysis(self, package_name: str) -> Dict[str, Any]:
        decompiled_dir = self.workspace.get_decompile_path(package_name)
        self.logger.info(f"[{package_name}] Running static analysis...")
        static_result = self.static_analyzer.analyze(self.apk_path, decompiled_dir)
        return static_result.to_dict()

    def _run_yara_scan(self, package_name: str) -> List:
        decompiled_dir = self.workspace.get_decompile_path(package_name)
        self.logger.info(f"[{package_name}] Running YARA scan...")
        return self.yara_scanner.scan_directory(decompiled_dir)

    def _log_verdict(self, package_name, verdict: Verdict, events, yara_hits, static_info):
        log_verdict_debug(
            logger=self.logger,
            package_name=package_name,
            score=verdict.score,
            verdict_label=verdict.label,
            reasons=verdict.reasons,
            events=events,
            yara_hits=yara_hits,
            static_info=static_info
        )
        
    def _error_result(self, package: str, base: Dict[str, Any], error_msg: str) -> Dict[str, Any]:
        return {
            **base,
            "apk_metadata": {
                **base.get("apk_metadata", {}),
                "analyzed_at": datetime.now(timezone.utc).isoformat(),
            },
            "static_analysis": {},
            "yara_matches": [],
            "dynamic_analysis": {
                "original_events": [],
                "aggregated_events": [],
                "summary": {}
            },
            "triggered_rule_results": [],
            "hook_event_counts": {},
            "classification": {
                "verdict": "error",
                "score": 0,
                "flags": ["evaluation_failed"],
                "cvss_risk_band": "Unknown"
            },
            "risk_breakdown": {
                "static_score": 0,
                "dynamic_score": 0,
                "yara_score": 0,
                "total_score": 0
            },
            "error": error_msg
        }

