import time
import frida
import json
from pathlib import Path
from tools.adb_tools import wake_and_unlock, launch_app_direct
from apk_inspector.analysis.dynamic.frida_multi_hook_mngr import FridaMultiHookManager
from apk_inspector.analysis.dynamic.hook_descovery import discover_hooks
from apk_inspector.utils.frida_utils import wait_for_process
from apk_inspector.analysis.dynamic.hook_validator import validate_hook_script


class FridaSessionManager:
    def __init__(
        self,
        package_name: str,
        hooks_dir: Path,
        helpers_path: Path,
        logger,
        timeout: int = 120,
        grace_period: int = 10,
        leave_app_running: bool = False
    ):
        self.package_name = package_name
        self.hooks_dir = hooks_dir
        self.helpers_path = helpers_path
        self.logger = logger
        self.timeout = timeout
        self.grace_period = grace_period
        self.leave_app_running = leave_app_running

    def _inject_helpers(self, session):
        try:
            helpers_code = self.helpers_path.read_text(encoding="utf-8")
            script = session.create_script(helpers_code)

            def on_message(msg, data):
                if msg["type"] == "error":
                    self.logger.error(f"[FRIDA ERROR] Helper error: {msg.get('stack', msg)}")

            script.on("message", on_message)
            script.load()
            self.logger.info("[FRIDA] Injected frida_helpers.js")
        except Exception as ex:
            self.logger.exception(f"[FRIDA ERROR] Failed to inject helpers: {ex}")

    def _validate_hooks(self, paths: list):
        for path in paths:
            for err in validate_hook_script(path):
                self.logger.warning(f"[HOOK VALIDATION] {path.name}: {err}")

    def run(self) -> list:
        events = []
        session = device = pid = None
        activity = None
        reported_hooks = set()

        try:
            import frida

            device = frida.get_usb_device(timeout=1000)

            try:
                pid = device.spawn([self.package_name])
                session = device.attach(pid)
                self.logger.info(f"[FRIDA] Spawned & attached to {self.package_name} (PID {pid})")
                device.resume(pid)
                time.sleep(2.0)
                time.sleep(self.grace_period)
                wake_and_unlock()
                if activity:
                    launch_app_direct(self.package_name, activity, self.logger)
            except frida.NotSupportedError as e:
                self.logger.warning(f"[FRIDA] spawn() failed: {e}. Falling back to attach().")
                pid = wait_for_process(device, self.package_name)
                session = device.attach(pid)
                self.logger.info(f"[FRIDA] Attached to already running process (PID {pid})")
                time.sleep(2.0)

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
            
            run_time = self.timeout if self.timeout else 120
            self.logger.info(f"[FRIDA] Run time set to {run_time} seconds")
            events = hook_mngr.run(run_duration=run_time)

            for evt in events:
                hook = evt.get("hook")
                if hook == "frida_helpers":
                    continue
                if hook:
                    reported_hooks.add(hook)

            expected_hooks = [info["metadata"]["name"] for info in hook_map.values() if "metadata" in info]
            self.logger.info(f"[FRIDA] Hook(s) that returned events: {sorted(reported_hooks)}")
            missing_hooks = sorted(set(expected_hooks) - reported_hooks)
            if missing_hooks:
                self.logger.warning(f"[FRIDA] Hook(s) loaded but returned no events: {missing_hooks}")

            try:
                self.logger.debug(f"[FRIDA] Sample Events: {json.dumps(events[:3], indent=2)}")
            except Exception as log_err:
                self.logger.warning(f"[FRIDA] Could not dump sample events: {log_err}")

            self.logger.debug(f"[FRIDA] Collected {len(events)} events. Sample:\n{events[:2]}")

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
            
        return valid_events
