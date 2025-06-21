
import re
import time
import json
from typing import List, Dict, Optional, Callable, Any
from pathlib import Path

class FridaMultiHookManager:
    def __init__(self, session, script_paths, logger, helpers_path=None,
                 frida_pid=None, on_event_callback=None, message_timeout=60,
                 metadata_map=None):
        self.session = session
        self.script_paths = script_paths
        self.logger = logger
        self.helpers_path = helpers_path
        self.frida_pid = frida_pid
        self.on_event_callback = on_event_callback
        self.message_timeout = message_timeout
        self.events = []
        self.hook_set = set()
        self.jvm_ready_flag = False
        self.metadata_map = metadata_map or {}
        
        self.jvm_ready_flag = False
        self.jvm_absence_reason = None

    def _get_combined_script(self, only_java=None) -> str:
        parts = []

        if self.helpers_path:
            try:
                helpers_code = self.helpers_path.read_text(encoding="utf-8")
                parts.append(f"// ===== Helpers =====\n{helpers_code}")
            except Exception as e:
                self.logger.warning(f"[FRIDA] ❌ Failed to include helpers: {e}")

        for path in self.script_paths:
            meta = self.metadata_map.get(path.name, {})
            is_java = meta.get("entrypoint") == "java"

            if only_java is True and not is_java:
                continue
            if only_java is False and is_java:
                continue

            try:
                hook_code = path.read_text(encoding="utf-8")
                parts.append(f"// ===== Hook: {path.name} =====\n{hook_code}")
            except Exception as e:
                self.logger.warning(f"[FRIDA] ❌ Failed to load hook {path.name}: {e}")

        return "\n\n".join(parts)

    def _on_message(self, msg, data=None):
        if msg.get("type") == "send":
            payload = msg.get("payload", {})

            if isinstance(payload, dict):
                msg_type = payload.get("type")

                if msg_type == "jvm_ready":
                    self.logger.info("[FRIDA] ✅ JVM ready signal received.")
                    self.jvm_ready_flag = True

                elif msg_type == "jvm_unavailable":
                    self.jvm_absence_reason = payload.get("reason", "Java VM never became ready")
                    self.logger.warning(f"[FRIDA] ❌ JVM unavailable: {self.jvm_absence_reason}")

                elif msg_type == "vm_probe_error":
                    err = payload.get("message", "Unknown VM probe error")
                    self.jvm_absence_reason = f"vm_probe_error: {err}"
                    self.logger.warning(f"[FRIDA] ❌ VM Probe error: {err}")

                # Collect runtime events
                payload.setdefault("pid", self.frida_pid or "unknown")
                payload.setdefault("hook", "unknown")

                if msg_type not in ["jvm_ready", "jvm_unavailable", "vm_probe_error"]:
                    self.events.append(payload)
                    hook_name = payload.get("hook")
                    if hook_name:
                        self.hook_set.add(hook_name)
                    if self.on_event_callback:
                        self.on_event_callback(payload)

        elif msg.get("type") == "error":
            self.logger.error(f"[FRIDA ERROR] {msg.get('stack', msg)}")

    def load_native_hooks(self):
        script_code = self._get_combined_script(only_java=False)
        script = self.session.create_script(script_code)
        script.on("message", self._on_message)
        script.load()
        self.logger.info(f"[FRIDA] ✅ Loaded native hooks")

    def load_java_hooks(self):
        script_code = self._get_combined_script(only_java=True)
        script = self.session.create_script(script_code)
        script.on("message", self._on_message)
        script.load()
        self.logger.info(f"[FRIDA] ✅ Loaded Java hooks")

    def _wait_for_jvm(self, timeout=60):
        self.logger.info("[FRIDA] ⏳ Waiting for JVM readiness...")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.jvm_ready_flag:
                self.logger.info("[FRIDA] ✅ JVM is ready.")
                return True
            time.sleep(0.5)
        self.jvm_absence_reason = "timeout"    
        self.logger.warning("[FRIDA] ❌ JVM wait timed out.")
        return False

    def run(self, run_duration=60):
        self.logger.info(f"[FRIDA] ▶ Starting hook manager for {run_duration}s...")

        self.load_native_hooks()

        jvm_ready = self._wait_for_jvm(timeout=self.message_timeout)
        if not jvm_ready:
            self.jvm_absence_reason = self.jvm_absence_reason or "never_initialized"
            self.logger.warning(f"[FRIDA] ❌ JVM never initialized. Reason: {self.jvm_absence_reason}")
        else:
            self.load_java_hooks()

        time.sleep(run_duration)

        self.logger.info(f"[FRIDA] ✅ Collected {len(self.events)} events.")
        return [e for e in self.events if isinstance(e, dict)]