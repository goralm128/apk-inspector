from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime, timezone
import yaml

from apk_inspector.analysis.dynamic.hook_descovery import discover_hooks
from apk_inspector.analysis.dynamic.dynamic_analyzer import DynamicAnalyzer
from apk_inspector.analysis.static.static_analyzer import StaticAnalyzer
from apk_inspector.analysis.yara_scanner import YaraScanner
from apk_inspector.rules.rule_engine import RuleEngine
from apk_inspector.reports.report_builder import APKReportBuilder
from apk_inspector.core.workspace_manager import WorkspaceManager
from apk_inspector.utils.logger import get_logger, log_verdict_debug
from apk_inspector.core.decompiler import decompile_apk
from apk_inspector.analysis.tag_inferencer.manifest import ManifestTagInferencer
from apk_inspector.analysis.tag_inferencer.regex import RegexTagInferencer
from apk_inspector.utils.yara_utils import ensure_yara_models
from apk_inspector.config.defaults import CONFIG_RULES_DIR
from apk_inspector.reports.models import Verdict


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

        hook_scripts = discover_hooks(self.hooks_dir, self.logger)
        if not hook_scripts:
            self.logger.error(f"[✗] No valid Frida hook scripts found in: {self.hooks_dir.resolve()}")
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
            static_result = self._perform_static_analysis(package_name)
            manifest_tags = self._infer_manifest_tags(static_result)

            raw_yara_matches = self._run_yara_scan(package_name)
            yara_models = ensure_yara_models(raw_yara_matches or [])

            tag_rules = self._load_tag_rules()
            regex_inferencer = RegexTagInferencer(tag_rules)

            dynamic_analyzer = DynamicAnalyzer(
                hooks_dir=self.hooks_dir,
                logger=self.logger,
                rule_engine=self.rule_engine,
                tag_inferencer=regex_inferencer,
                run_dir=self.run_dir,
                timeout=self.timeout
            )
            self.report_builder.set_hook_metadata(dynamic_analyzer.hook_metadata_map)

            dyn_res = dynamic_analyzer.analyze(package_name, apk_metadata={
                "package_name": package_name,
                "apk_name": self.apk_path.name,
                "apk_path": str(self.apk_path)
            })
            events = dyn_res.get("events", [])
            hook_counts = dyn_res.get("hook_event_counts", {})
            self.logger.info(f"[{package_name}] Dynamic analysis collected {len(events)} events.")

            dynamic_tags = list(set(tag for e in events for tag in regex_inferencer.infer_tags(e)))
            all_tags = sorted(set(manifest_tags + dynamic_tags))
            self.logger.info(f"[{package_name}] Inferred tags: {all_tags}")

            verdict = self.rule_engine.evaluate(
                events=events,
                yara_hits=[m.__dict__ for m in yara_models],
                static_info=static_result.to_dict(),
                hook_coverage=hook_counts
            )
            self._log_verdict(package_name, verdict, events, raw_yara_matches, static_result.to_dict())

            self.report_builder.set_static_analysis_result(static_result)
            self.report_builder.set_yara_matches(yara_models)
            self.report_builder.merge_hook_result({
                "events": events,
                "hook_event_counts": hook_counts,
                "verdict": verdict
            })

            final_report = self.report_builder._assemble_report(events, verdict, verdict.triggered_rule_results)
            final_report["inferred_tags"] = all_tags
            return {**base_report, **final_report}

        except Exception as ex:
            self.logger.exception(f"[{package_name}] Fatal error during inspection: {ex}")
            return self._error_result(package_name, base_report, str(ex))

    def _ensure_decompiled(self, package_name: str):
        decompiled_dir = self.workspace.get_decompile_path(package_name)
        if not decompiled_dir.exists() or not any(decompiled_dir.iterdir()):
            self.logger.info(f"[{package_name}] Decompiled folder missing or empty. Starting decompilation...")
            self.workspace.create_decompile_dir(package_name)
            self.decompiled_dir, self.decompiler_backend, self.androguard_apk = decompile_apk(self.apk_path, decompiled_dir)
        else:
            self.logger.info(f"[{package_name}] Reusing existing decompiled code.")
            self.decompiled_dir = decompiled_dir
            self.decompiler_backend = "apktool"
            self.androguard_apk = None

    def _perform_static_analysis(self, package_name: str):
        self.logger.debug(f"[{package_name}] Running static analysis with backend: {self.decompiler_backend}")
        return self.static_analyzer.analyze(
            apk_path=self.apk_path,
            decompiled_path=self.decompiled_dir,
            backend=self.decompiler_backend
        )

    def _run_yara_scan(self, package_name: str) -> List:
        decompiled_dir = self.workspace.get_decompile_path(package_name)
        self.logger.info(f"[{package_name}] Running YARA scan...")
        return self.yara_scanner.scan_directory(decompiled_dir)

    def _load_tag_rules(self) -> Dict[str, Any]:
        try:
            with (CONFIG_RULES_DIR / "tag_rules.yaml").open("r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            self.logger.warning(f"[✗] Failed to load tag rules: {e}")
            return {}

    def _infer_manifest_tags(self, static_result) -> List[str]:
        manifest = static_result.manifest_analysis
        tags = ManifestTagInferencer().infer_tags(manifest)
        self.logger.info(f"[{self.report_builder.package}] Inferred static tags: {tags}")
        return tags

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
            "static_analysis": {
                "manifest_analysis": {},
                "static_warnings": [],
                "string_matches": [],
                "certificate": {},
                "strings_xml_issues": [],
                "log_leaks": []
            },
            "yara_matches": [],
            "dynamic_analysis": {
                "original_events": [],
                "aggregated_events": [],
                "summary": {}
            },
            "triggered_rule_results": [],
            "hook_event_counts": {},
            "hook_coverage_percent": 0.0,
            "report_summary": {
                "classification": {
                    "verdict": "error",
                    "score": 0,
                    "flags": ["evaluation_failed"],
                    "cvss_risk_band": "Unknown"
                },
                "risk_breakdown": {
                    "static_score": 0,
                    "dynamic_score": 0,
                    "dynamic_rule_bonus": 0,
                    "yara_score": 0,
                    "hook_score": 0,
                    "total_score": 0
                }
            },
            "error": error_msg
        }
