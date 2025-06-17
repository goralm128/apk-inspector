import time
import asyncio
import frida
import json
from pathlib import Path

from tools.adb_tools import wake_and_unlock, launch_main_activity, launch_app_direct
from apk_inspector.analysis.dynamic.frida_multi_hook_mngr import FridaMultiHookManager
from apk_inspector.analysis.dynamic.hook_descovery import discover_hooks
from apk_inspector.utils.frida_utils import wait_for_process, wait_for_java_vm
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
        timeout,
        grace_period=5,
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

    def _validate_hooks(self, paths):
        for path in paths:
            for err in validate_hook_script(path):
                self.logger.warning(f"[HOOK VALIDATION] {path.name}: {err}")

    def run(self):
        """Sync-compatible wrapper for async run."""
        return asyncio.run(self.run_async())

    async def run_async(self):
        events = []
        session = device = pid = None
        reported_hooks = set()
        missing_hooks = []

        try:
            device = frida.get_usb_device(timeout=1000)
            self.logger.info(f"[FRIDA] Using USB device: {device.name}")

            wake_and_unlock()

            self.logger.info(f"[FRIDA] Spawning process for {self.package_name}")
            pid = device.spawn([self.package_name])
            session = device.attach(pid)
            self.logger.info(f"[FRIDA] Spawned and attached to PID {pid}")

            hook_map = discover_hooks(self.hooks_dir, logger=self.logger)
            hook_paths = [info["path"] for info in hook_map.values()]
            self._validate_hooks(hook_paths)

            hook_mngr = FridaMultiHookManager(
                session=session,
                script_paths=hook_paths,
                logger=self.logger,
                helpers_path=self.helpers_path
            )

            self.logger.info(f"[FRIDA] Resuming process PID {pid}")
            device.resume(pid)
            
            self.logger.info(f"[FRIDA] Waiting for Java VM to become available...")
            await asyncio.sleep(20)  # Give the VM time to initialize before check
            java_ready = await wait_for_java_vm(session, self.logger, timeout=60)

            if not java_ready:
                self.logger.warning("[FRIDA] Java VM still not available after 60s")

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
