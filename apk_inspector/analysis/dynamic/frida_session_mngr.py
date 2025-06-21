import asyncio
import frida
from pathlib import Path
import time
from apk_inspector.analysis.dynamic.frida_multi_hook_mngr import FridaMultiHookManager
from apk_inspector.analysis.dynamic.hook_descovery import discover_hooks
from apk_inspector.utils.frida_utils import wait_for_java_vm
from tools.adb_tools import wake_and_unlock
from apk_inspector.analysis.dynamic.frida_session import FridaSession


class FridaSessionManager:
    def __init__(self, package_name, hooks_dir, helpers_path, run_dir, logger,
                 timeout=60, grace_period=5, leave_app_running=False):
        self.package_name = package_name
        self.hooks_dir = hooks_dir
        self.helpers_path = helpers_path
        self.run_dir = run_dir
        self.logger = logger
        self.timeout = timeout
        self.grace_period = grace_period
        self.leave_app_running = leave_app_running
        
    def _on_event_callback(self, event):
        if not isinstance(event, dict):
            self.logger.warning("[FRIDA CALLBACK] Invalid event format")
            return
        hook = event.get("hook", "unknown")
        action = event.get("action", "no-action")
        self.logger.debug(f"[EVENT] {hook} → {action}")    

    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(self.run_async())
        finally:
            asyncio.set_event_loop(None)


    async def run_async(self):
        self.logger.info(f"[FRIDA] ▶ Starting session for {self.package_name}")
        events = []
        reported_hooks = set()
        missing_hooks = []

        java_vm_ready = True
        jvm_absence_reason = None
        session = None

        try:
            # ─── Device connection ──────────────────────────────
            device = frida.get_usb_device(timeout=1000)
            self.logger.info(f"[FRIDA] Connected to device: {device.name}")
            wake_and_unlock()

            # ─── Hook discovery ─────────────────────────────────
            hook_map = discover_hooks(self.hooks_dir, logger=self.logger)
            hook_paths = [info["path"] for info in hook_map.values()]
            metadata_map = {info["path"].name: info.get("metadata", {}) for info in hook_map.values()}
            expected_hooks = [meta.get("name") for meta in metadata_map.values() if meta.get("name")]

            java_hook_paths = [p for p in hook_paths if metadata_map.get(p.name, {}).get("entrypoint") == "java"]

            # ─── Session instantiation ──────────────────────────
            session = FridaSession(device, self.package_name, self.logger)

            # ─── Hook manager (shared across children) ──────────
            hook_mgr = FridaMultiHookManager(
                session=None,  # updated later
                script_paths=hook_paths,
                logger=self.logger,
                helpers_path=self.helpers_path,
                frida_pid=None,
                on_event_callback=self._on_event_callback,  # define this in your class
                metadata_map=metadata_map
            )

            # ─── Spawn gating and child PID hook prep ───────────
            session.enable_spawn_gating(
                hook_manager=hook_mgr,
                java_hook_paths=java_hook_paths,
                timeout=45
            )

            # ─── Attach to app ──────────────────────────────────
            session.spawn_and_attach()
            session.resume()

            # ─── JVM readiness probe ─────────────────────────────
            java_vm_ready = await session.wait_for_java_vm(
                probe_path="frida/helpers/vm_probe.js",
                timeout=60
            )

            if not java_vm_ready:
                jvm_absence_reason = "timeout or Java VM never initialized in app"
                self.logger.warning(f"[FRIDA] ❌ JVM never initialized. Reason: {jvm_absence_reason}")

            # ─── Bootstrap hooks (optional) ─────────────────────
            bootstrap_path = Path("frida/hooks/hook_bootstrap_native.js")
            if bootstrap_path.exists():
                session.load_script_from_file(bootstrap_path)

            # ─── Update hook manager ────────────────────────────
            hook_mgr.session = session.session
            hook_mgr.frida_pid = session.pid

            # ─── Run hook loop ──────────────────────────────────
            events = hook_mgr.run(run_duration=self.timeout)

            # ─── Final JVM sanity check ─────────────────────────
            if not hook_mgr.jvm_ready_flag:
                java_vm_ready = False
                jvm_absence_reason = hook_mgr.jvm_absence_reason or jvm_absence_reason or "unknown"
                self.logger.warning(f"[FRIDA] ❌ JVM was not ready for Java hooks: {jvm_absence_reason}")

            # ─── Final hook stats ───────────────────────────────
            for e in events:
                hook = e.get("hook")
                if hook and hook != "frida_helpers":
                    reported_hooks.add(hook)

            missing_hooks = sorted(set(expected_hooks) - reported_hooks)
            if missing_hooks:
                self.logger.warning(f"[FRIDA] Hooks NOT triggered: {missing_hooks}")
            self.logger.info(f"[FRIDA] Hooks triggered: {sorted(reported_hooks)}")

        except Exception as ex:
            self.logger.exception(f"[FRIDA ERROR] during session: {ex}")

        finally:
            if session:
                session.cleanup(kill_process=not self.leave_app_running)
                session.disable_spawn_gating()

            # DO NOT call frida.shutdown() here — it breaks the next analysis run!
            # This MUST be managed only once globally if ever used.

        return {
            "events": events,
            "reported_hooks": sorted(reported_hooks),
            "missing_hooks": missing_hooks,
            "java_vm_ready": java_vm_ready,
            "jvm_absence_reason": jvm_absence_reason
        }
