from apk_inspector.utils.frida_runner import trace_frida_events
from apk_inspector.core.adb_tools import wake_and_unlock, launch_app, force_stop_app, is_device_connected
from apk_inspector.utils.file_utils import is_private_ip, deduplicate_events
from apk_inspector.analysis.data_classifier import classify_path
from apk_inspector.utils.fs_utils import extract_file_path


class DynamicAnalyzer:
    def __init__(self, hook_scripts, logger, timeout=10):
        self.hook_scripts = hook_scripts
        self.logger = logger
        self.timeout = timeout

    def analyze(self, package_name: str) -> list:
        all_events = []
        self.logger.info(f"[{package_name}] Starting dynamic analysis with {len(self.hook_scripts)} hooks")
        for hook_name, script in self.hook_scripts.items():
            self.logger.info(f"[{package_name}] Hook: {hook_name}")
            try:
                wake_and_unlock()
                launch_app(package_name)
                events = trace_frida_events(package_name, script, timeout=self.timeout)

                # Tag the hook source
                for e in events:
                    e["source_hook"] = hook_name
                    # Apply classify_path() if event has a relevant file path
                    file_path = extract_file_path(e)
                    if file_path:
                        e["path_type"] = classify_path(file_path)

                if hook_name == "network":
                    events = [e for e in events if not (ip := e.get("address", {}).get("ip")) or not is_private_ip(ip)]

                all_events.extend(deduplicate_events(events))

            except Exception as e:
                self.logger.exception(f"[{package_name}] Hook '{hook_name}' failed: {e}")
            finally:
                if is_device_connected():
                    # Ensure the app is stopped after each hook
                    self.logger.info(f"[{package_name}] Stopping app after hook: {hook_name}")
                    force_stop_app(package_name)

        return all_events
