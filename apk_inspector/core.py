import logging
import json
import time
from pathlib import Path
import pandas as pd

# --- Constants ---
DEFAULT_LOG_PATH = Path("output/apk_inspector.log")

# --- Internal Modules ---
from apk_inspector.utils.rule_engine import RuleEngine, load_rules_from_yaml
from apk_inspector.utils.adb_tools import (
    wake_and_unlock, launch_app, force_stop_app, is_device_connected, check_device_compatibility
)
from apk_inspector.utils.hook_utils import discover_hooks
from apk_inspector.utils.apk_utils import install_apks, save_results
from apk_inspector.utils.frida_utils import trace_frida_events
from apk_inspector.utils.classifier import classify_path
from apk_inspector.utils.file_utils import is_private_ip, deduplicate_events, clear_output_file, write_results
from apk_inspector.utils.decompiler import decompile_apk
from apk_inspector.utils.yara_scanner import scan_with_yara, yara_matches_to_dataframe
from apk_inspector.static_analysis.static_runner import run_static_analysis
from apk_inspector.utils.rule_utils import validate_rules_yaml


def setup_logger(verbose: bool = False, log_path: Path = DEFAULT_LOG_PATH) -> logging.Logger:
    """Initializes and returns a configured logger."""
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = "[%(levelname)s] %(asctime)s - %(message)s"
    log_path.parent.mkdir(exist_ok=True)

    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8", mode="w"),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("APKInspector")


class APKInspector:
    """
    Main class for running static and dynamic analysis on APK files using Frida, YARA, and scoring rules.
    """

    def __init__(self, hooks_dir: Path, apk_dir: Path, output_file: Path, logger: logging.Logger):
        self.hooks_dir = hooks_dir
        self.apk_dir = apk_dir
        self.output_file = output_file
        self.logger = logger

        self.hook_scripts = discover_hooks(hooks_dir)
        if not self.hook_scripts:
            raise FileNotFoundError(f"No hook scripts found in {hooks_dir}")

        rules_path = Path(__file__).parent.parent / "rules" / "rules.yaml"
        validate_rules_yaml(rules_path)
        rules = load_rules_from_yaml(rules_path)
        self.rule_engine = RuleEngine(rules)

    def filter_private_network_events(self, events):
        return [
            e for e in events
            if not (ip := e.get("address", {}).get("ip")) or not is_private_ip(ip)
        ]

    def trace_package(self, package, script, hook_name, include_private, timeout,
                      yara_results=None, static_report=None):
        if not is_device_connected():
            self.logger.error(f"No Android device connected. Skipping: {package}")
            return {
                "package": package, "events": [], "score": 0, "verdict": "error",
                "yara_matches": yara_results or [], "static_analysis": static_report or {}
            }

        try:
            wake_and_unlock()
            launch_app(package)
            time.sleep(2)

            self.logger.debug(f"Launching Frida tracing for {package}...")
            events = trace_frida_events(package, script, timeout=timeout)

            if hook_name == "network" and not include_private:
                events = self.filter_private_network_events(events)

            events = deduplicate_events(events)

            for e in events:
                if "path" in e:
                    e["classification"] = classify_path(e["path"])

            app_eval = self.rule_engine.evaluate(events)

            save_results(
                package_name=package,
                events=events,
                score=app_eval.score,
                verdict=app_eval.label,
                yara_matches=yara_results,
                reasons=app_eval.reasons
            )

            self.logger.info(
                f"[{package}] Verdict: {app_eval.label} | Score: {app_eval.score} | Events: {len(events)}"
            )

            return {
                "package": package,
                "events": events,
                "score": app_eval.score,
                "verdict": app_eval.label,
                "reasons": app_eval.reasons,
                "yara_matches": yara_results or [],
                "static_analysis": static_report or {}
            }

        except Exception as e:
            self.logger.exception(f"[{package}] Tracing failed: {e}")
            save_results(package, [], score=0, verdict="error")
            return {
                "package": package, "events": [], "score": 0, "verdict": "error",
                "yara_matches": yara_results or [], "static_analysis": static_report or {}
            }

        finally:
            if is_device_connected():
                force_stop_app(package)
            else:
                self.logger.warning(f"Device disconnected before cleanup: {package}")

    def run(self, hook_name, include_private=False, timeout=10):
        if not is_device_connected():
            self.logger.error("No Android device connected. Aborting analysis.")
            return

        if hook_name not in self.hook_scripts:
            raise ValueError(f"Unsupported hook: {hook_name}")

        try:
            check_device_compatibility()
        except RuntimeError as e:
            self.logger.fatal(f"[FATAL] {e}")
            return

        script = self.hook_scripts[hook_name]
        clear_output_file(self.output_file)

        self.logger.info("Installing APKs...")
        packages = install_apks(self.apk_dir)

        results = []
        for pkg in packages:
            self.logger.info(f"[{pkg}] Static analysis starting...")
            apk_file = self.apk_dir / f"{pkg}.apk"
            decompiled_path = Path("decompiled") / pkg

            try:
                decompiled_path.mkdir(parents=True, exist_ok=True)
                decompile_apk(apk_file, decompiled_path)
                yara_results = scan_with_yara(decompiled_path)
                static_report = run_static_analysis(apk_file, decompiled_path)

                if yara_results:
                    df = yara_matches_to_dataframe(yara_results)
                    df.to_csv(f"output/{pkg}_yara_matches.csv", index=False)

            except Exception as e:
                self.logger.warning(f"[{pkg}] Static analysis failed: {e}")
                yara_results = []
                static_report = {}

            self.logger.info(f"[{pkg}] Dynamic analysis starting...")
            result = self.trace_package(pkg, script, hook_name, include_private, timeout, yara_results, static_report)
            results.append(result)

        write_results(self.output_file, results)

        yara_summary_path = Path("output/yara_results.json")
        yara_summary = {r["package"]: r.get("yara_matches", []) for r in results}

        with yara_summary_path.open("w", encoding="utf-8") as f:
            json.dump(yara_summary, f, indent=2, ensure_ascii=False)

        self.logger.info(f"[✓] YARA summary saved to: {yara_summary_path.resolve()}")
        self.logger.info(f"[✓] Completed analysis on {len(packages)} apps.")
        self.logger.info(f"[✓] Full results saved to: {self.output_file.resolve()}")
