import time
import frida
from pathlib import Path
from tools.adb_tools import wake_and_unlock, launch_app_direct
from apk_inspector.analysis.dynamic.frida_multi_hook_mngr import FridaMultiHookManager
from apk_inspector.utils.hook_loader import load_hook_with_helpers
from apk_inspector.utils.hook_descovery import discover_hooks
from apk_inspector.utils.frida_utils import wait_for_process


POLL_INTERVAL = 0.5


class FridaSessionManager:
    def __init__(
        self,
        package_name: str,
        hooks_dir: Path,
        helpers_path: Path,
        logger,
        timeout: int = 10,
        grace_period: int = 5,
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

            def on_helper_message(msg, data):
                if msg["type"] == "error":
                    self.logger.error(f"[FRIDA ERROR] Helper error: {msg.get('stack', msg)}")

            script.on("message", on_helper_message)
            script.load()
            self.logger.info("[FRIDA] Injected frida_helpers.js")
        except Exception as e:
            self.logger.exception(f"[FRIDA ERROR] Failed to inject helpers: {e}")

    def run(self) -> list:
        events = []
        pid, session, device = None, None, None
        activity = None

        try:
            device = frida.get_usb_device(timeout=1000)
            try:
                pid = device.spawn([self.package_name])
                session = device.attach(pid)
                self.logger.info(f"[FRIDA] Spawned & attached to {self.package_name} (PID {pid})")
                device.resume(pid)
                time.sleep(2.0)
                wake_and_unlock()
                if activity:
                    launch_app_direct(self.package_name, activity, self.logger)
            except frida.NotSupportedError as spawn_err:
                self.logger.warning(f"[FRIDA] spawn() failed: {spawn_err}. Falling back to attach().")
                if activity:
                    launch_app_direct(self.package_name, activity, self.logger)
                pid = wait_for_process(device, self.package_name)
                session = device.attach(pid)
                self.logger.info(f"[FRIDA] Attached to already running process (PID {pid})")

            # Step 1: Inject helpers
            self._inject_helpers(session)

            # Step 2: Load hooks
            hook_map = discover_hooks(self.hooks_dir, logger=self.logger)
            hook_paths = [info["path"] for info in hook_map.values()]
            hook_mngr = FridaMultiHookManager(session, hook_paths, self.logger, helpers_path=self.helpers_path)
            events = hook_mngr.run(run_duration=self.timeout)

        except Exception as e:
            self.logger.exception(f"[FRIDA ERROR] Tracing failed for {self.package_name}: {e}")

        finally:
            try:
                if session:
                    session.detach()
                if pid and not self.leave_app_running:
                    device.kill(pid)
            except Exception as cleanup_err:
                self.logger.warning(f"[FRIDA WARNING] Cleanup failed: {cleanup_err}")

        return events