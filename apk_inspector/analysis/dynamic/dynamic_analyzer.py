from pathlib import Path
from apk_inspector.analysis.dynamic.frida_session_mngr import FridaSessionManager
from apk_inspector.utils.file_utils import deduplicate_events, is_private_ip
from apk_inspector.analysis.score_event import score_event
from apk_inspector.utils.fs_utils import extract_file_path
from apk_inspector.analysis.data_classifier import classify_path
from tools.adb_tools import is_device_connected, force_stop_app
from apk_inspector.analysis.dynamic.hook_categories import HOOK_CATEGORY_MAP


class DynamicAnalyzer:
    def __init__(self, hooks_dir: Path, logger, timeout=10, grace_period=5):
        self.hooks_dir = hooks_dir
        self.logger = logger
        self.timeout = timeout
        self.grace_period = grace_period
        self.helpers_path = Path("frida/helpers/frida_helpers.js")

    def _process_event(self, event):
        hook_name = event.get("hook", "unknown")
        event["source_hook"] = hook_name

        # Add category based on hook name
        event["category"] = HOOK_CATEGORY_MAP.get(hook_name, "uncategorized")
        if event["category"] == "uncategorized":
            self.logger.warning(f"Uncategorized hook: {hook_name}")

        score_val, risk_label, justification = score_event(event, return_justification=True)
        event.update({
            "score": score_val,
            "label": risk_label,
            "justification": justification
        })

        file_path = extract_file_path(event)
        if file_path:
            event["path_type"] = classify_path(file_path)

        return event
    
    def analyze(self, package_name: str) -> list:
        self.logger.info(f"[{package_name}] Starting dynamic analysis with hooks in {self.hooks_dir}")

        try:
            frida_session_mngr = FridaSessionManager(
                package_name=package_name,
                hooks_dir=self.hooks_dir,
                helpers_path=self.helpers_path,
                logger=self.logger,
                timeout=self.timeout,
                grace_period=self.grace_period
            )

            raw_events = frida_session_mngr.run()
            self.logger.info(f"[{package_name}] Collected {len(raw_events)} raw events")

            processed = [self._process_event(e) for e in raw_events]

            before = len(processed)
            processed = [
                e for e in processed
                if not (ip := e.get("address", {}).get("ip")) or not is_private_ip(ip)
            ]
            self.logger.info(f"[{package_name}] Filtered {before - len(processed)} local IP events")

            deduped = deduplicate_events(processed)
            self.logger.info(f"[{package_name}] Final deduplicated events: {len(deduped)}")

            return deduped

        except Exception as e:
            self.logger.exception(f"[{package_name}] Dynamic analysis failed: {e}")
            return []

        finally:
            if is_device_connected():
                self.logger.info(f"[{package_name}] Stopping app after analysis")
                force_stop_app(package_name)
