from pathlib import Path
import time

from apk_inspector.utils.adb_tools import (
    wake_and_unlock, launch_app, force_stop_app, is_device_connected, check_device_compatibility
)
from apk_inspector.utils.hook_utils import discover_hooks
from apk_inspector.utils.apk_utils import install_apks, save_results
from apk_inspector.utils.frida_utils import trace_frida_events
from apk_inspector.utils.classifier import classify_path
from apk_inspector.utils.file_utils import (
    is_private_ip, deduplicate_events, clear_output_file, write_results
)


class APKInspector:
    def __init__(self, hooks_dir: Path, apk_dir: Path, output_file: Path):
        self.hooks_dir = hooks_dir
        self.apk_dir = apk_dir
        self.output_file = output_file
        self.hook_scripts = discover_hooks(hooks_dir)

        if not self.hook_scripts:
            raise FileNotFoundError(f"No hook scripts found in {hooks_dir}")

    def filter_private_network_events(self, events):
        return [
            e for e in events
            if not (ip := e.get("address", {}).get("ip")) or not is_private_ip(ip)
        ]

    def trace_package(self, package, script, hook_name, include_private, timeout):
        if not is_device_connected():
            print(f"[ERROR] No Android device connected. Skipping: {package}")
            return {"package": package, "events": []}

        try:
            wake_and_unlock()
            launch_app(package)
            time.sleep(2)

            events = trace_frida_events(package, script, timeout=timeout)

            if hook_name == "network" and not include_private:
                events = self.filter_private_network_events(events)

            events = deduplicate_events(events)

            for e in events:
                if "path" in e:
                    e["classification"] = classify_path(e["path"])

            save_results(package, events)
            return {"package": package, "events": events}

        except Exception as e:
            print(f"[ERROR] Tracing failed for {package}: {e}")
            save_results(package, [])
            return {"package": package, "events": []}

        finally:
            if is_device_connected():
                force_stop_app(package)
            else:
                print(f"[WARN] Device disconnected before cleanup: {package}")

    def run(self, hook_name, include_private=False, timeout=10):
        if hook_name not in self.hook_scripts:
            raise ValueError(f"Unsupported hook: {hook_name}")

        # ✅ Device compatibility check
        try:
            check_device_compatibility()
        except RuntimeError as e:
            print(f"[FATAL] {e}")
            return

        script = self.hook_scripts[hook_name]
        clear_output_file(self.output_file)

        print("Installing APKs...")
        packages = install_apks(self.apk_dir)

        results = []
        for pkg in packages:
            print(f"Tracing '{hook_name}' behavior for: {pkg}")
            result = self.trace_package(pkg, script, hook_name, include_private, timeout)
            results.append(result)

        write_results(self.output_file, results)
        print(f"Completed analysis on {len(packages)} apps.")
        print(f"Results saved to {self.output_file}")