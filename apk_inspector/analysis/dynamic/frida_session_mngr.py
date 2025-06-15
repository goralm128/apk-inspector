import time
import frida
import json
from pathlib import Path
from tools.adb_tools import wake_and_unlock, launch_main_activity, launch_app_direct
from apk_inspector.analysis.dynamic.frida_multi_hook_mngr import FridaMultiHookManager
from apk_inspector.analysis.dynamic.hook_descovery import discover_hooks
from apk_inspector.utils.frida_utils import wait_for_process
from apk_inspector.analysis.dynamic.hook_validator import validate_hook_script
from apk_inspector.config.defaults import get_apk_path
from apk_inspector.utils.apk_utils import normalize_activity


class FridaSessionManager:
    def __init__(
        self,
        package_name,
        hooks_dir,
        helpers_path,
        run_dir,
        logger,
        timeout=120,
        grace_period=10,
        leave_app_running=False
    ):
        self.package_name = package_name
        self.hooks_dir = hooks_dir
        self.helpers_path = helpers_path
        self.run_dir = run_dir
        self.logger = logger
        self.timeout = timeout
        self.grace_period = grace_period
        self.leave_app_running = leave_app_running

    def _inject_helpers(self, session):
        try:
            code = self.helpers_path.read_text(encoding="utf-8")
            script = session.create_script(code)
            script.on("message", lambda msg, _: self._log_script_message(msg))
            script.load()
            self.logger.info("[FRIDA] Injected frida_helpers.js")
        except Exception as ex:
            self.logger.exception(f"[FRIDA] Failed to inject helpers: {ex}")

    def _log_script_message(self, msg):
        if msg["type"] == "error":
            self.logger.error(f"[FRIDA ERROR] Helper error: {msg.get('stack', msg)}")

    def _validate_hooks(self, paths):
        for path in paths:
            for err in validate_hook_script(path):
                self.logger.warning(f"[HOOK VALIDATION] {path.name}: {err}")

    def run(self):
        events = []
        session = device = pid = None
        reported_hooks = set()
        missing_hooks = []

        try:
            device = frida.get_usb_device(timeout=1000)
            self.logger.info(f"[FRIDA] Using USB device: {device.name}")

            # Wake device and launch app manually
            wake_and_unlock()
            activity = launch_main_activity(self.package_name, self.run_dir, self.logger)

            if activity:
                launched = launch_app_direct(self.package_name, activity, self.logger)
                if not launched:
                    self.logger.warning("[FRIDA] Failed to launch resolved main activity.")
            else:
                self.logger.warning("[FRIDA] No launchable activity found.")

            # Wait for process to show up
            self.logger.info(f"[FRIDA] Waiting for running process: {self.package_name}")
            try:
                pid = wait_for_process(device, self.package_name, timeout=30)
            except Exception as e:
                self.logger.error(f"[FRIDA ERROR] Target process vanished before attach: {e}")
                return self._format_results([], set(), [])

            # Attach once app is running
            session = device.attach(pid)
            self.logger.info(f"[FRIDA] Attached to running process (PID {pid})")

            # Give VM time to stabilize
            #time.sleep(8 + self.grace_period)
            time.sleep(20)

            self._inject_helpers(session)

            hook_map = discover_hooks(self.hooks_dir, logger=self.logger)
            hook_paths = [info["path"] for info in hook_map.values()]
            self._validate_hooks(hook_paths)

            self.logger.info(f"[FRIDA] Loading {len(hook_paths)} hook scripts...")
            for hook_file in hook_paths:
                self.logger.debug(f"[FRIDA] Hook file: {hook_file}")

            hook_mngr = FridaMultiHookManager(
                session=session,
                script_paths=hook_paths,
                logger=self.logger,
                helpers_path=self.helpers_path
            )

            self.logger.info(f"[FRIDA] Run time set to {self.timeout} seconds")
            events = hook_mngr.run(run_duration=self.timeout)

            for evt in events:
                hook = evt.get("hook")
                if hook and hook != "frida_helpers":
                    reported_hooks.add(hook)

            expected_hooks = [info["metadata"]["name"] for info in hook_map.values() if "metadata" in info]
            missing_hooks = sorted(set(expected_hooks) - reported_hooks)

            self.logger.info(f"[FRIDA] Hook(s) that returned events: {sorted(reported_hooks)}")
            if missing_hooks:
                self.logger.warning(f"[FRIDA] Hook(s) loaded but returned no events: {missing_hooks}")

            try:
                self.logger.debug(f"[FRIDA] Sample Events: {json.dumps(events[:3], indent=2)}")
            except Exception as log_err:
                self.logger.warning(f"[FRIDA] Could not dump sample events: {log_err}")

        except Exception as ex:
            self.logger.exception(f"[FRIDA ERROR] Tracing failed for {self.package_name}: {ex}")

        finally:
            if session:
                try:
                    session.detach()
                except Exception as ex:
                    self.logger.warning(f"[FRIDA WARNING] Detach failed: {ex}")
            if pid and not self.leave_app_running:
                try:
                    if pid in [p.pid for p in device.enumerate_processes()]:
                        device.kill(pid)
                except Exception as ex:
                    self.logger.warning(f"[FRIDA WARNING] Cleanup failed: {ex}")

        valid_events = [e for e in events if isinstance(e, dict)]
        if len(valid_events) != len(events):
            self.logger.warning(f"[FRIDA] Dropped {len(events) - len(valid_events)} malformed events.")

        return self._format_results(valid_events, reported_hooks, missing_hooks)

    def _format_results(self, events, reported_hooks, missing_hooks):
        return {
            "events": events,
            "reported_hooks": sorted(reported_hooks),
            "missing_hooks": missing_hooks
        }
