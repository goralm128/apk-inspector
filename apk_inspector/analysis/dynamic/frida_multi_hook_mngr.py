
import re
import time
import json
from typing import List, Dict, Optional, Callable, Any
from pathlib import Path

class FridaMultiHookManager:
    def __init__(
        self,
        session,
        script_paths: List[Path],
        logger,
        helpers_path: Optional[Path] = None,
        on_event_callback: Optional[Callable[[dict], None]] = None,
        message_timeout: int = 30
    ):
        self.session = session
        self.script_paths = script_paths
        self.logger = logger
        self.helpers_path = helpers_path
        self.on_event_callback = on_event_callback
        self.message_timeout = message_timeout
        self.events: List[Dict[str, Any]] = []

    def _normalize_metadata_constant(self, code: str) -> str:
        """
        Normalize all hook-local `const metadata_xyz = {...}` to `const metadata = {...}`
        to avoid naming collisions when combining multiple hooks.
        """
        return re.sub(r'const\s+metadata_\w+\s*=', 'const metadata =', code)

    def _get_combined_script(self) -> str:
        parts = []

        if self.helpers_path:
            try:
                helpers_code = self.helpers_path.read_text(encoding="utf-8")
                parts.append(f"// ===== Helpers =====\n{helpers_code}")
            except Exception as ex:
                self.logger.warning(f"[FRIDA] Failed to read helpers: {ex}")

        for path in self.script_paths:
            try:
                hook_code = path.read_text(encoding="utf-8")
                normalized_code = self._normalize_metadata_constant(hook_code)
                parts.append(f"// ===== Hook: {path.name} =====\n{normalized_code}")
            except Exception as ex:
                self.logger.warning(f"[FRIDA] Failed to read {path.name}: {ex}")

        return "\n\n".join(parts)

    def _on_message(self, msg, data):
        if msg["type"] == "send":
            payload = msg.get("payload", {})
            if isinstance(payload, dict):
                payload["hook"] = payload.get("hook", "unknown")
                self.events.append(payload)
                self.logger.debug(f"[FRIDA EVENT][{payload['hook']}] {payload}")
                if self.on_event_callback:
                    try:
                        self.on_event_callback(payload)
                    except Exception as cb_ex:
                        self.logger.warning(f"[FRIDA] on_event_callback error: {cb_ex}")
            else:
                self.logger.warning(f"[FRIDA] Non-dict payload: {payload}")
        elif msg["type"] == "error":
            self.logger.error(f"[FRIDA ERROR] {msg.get('stack', msg)}")
        else:
            self.logger.debug(f"[FRIDA MESSAGE] {msg}")

    def load_all_hooks(self):
        try:
            full_script = self._get_combined_script()
            script = self.session.create_script(full_script)
            script.on("message", self._on_message)
            script.load()
            self.logger.info(f"[FRIDA] Successfully loaded merged script for {len(self.script_paths)} hooks.")
        except Exception as ex:
            self.logger.exception(f"[FRIDA ERROR] Failed to load combined script: {ex}")

    def wait_for_activity(self, timeout: int = 60) -> bool:
        self.logger.info(f"[FRIDA] Waiting up to {timeout}s for hook activity...")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.events:
                return True
            time.sleep(0.5)
        self.logger.warning("[FRIDA] No hook activity detected within timeout.")
        return False

    def run(self, run_duration: int = 60) -> List[dict]:
        self.logger.info(f"[FRIDA] Running hook manager for {run_duration}s...")
        self.load_all_hooks()
        self.wait_for_activity(timeout=self.message_timeout)

        if run_duration > 0:
            self.logger.debug(f"[FRIDA] Collecting runtime events for {run_duration}s...")
            time.sleep(run_duration)

        valid_events = [e for e in self.events if isinstance(e, dict)]
        if len(valid_events) != len(self.events):
            self.logger.warning(f"[FRIDA] Dropped {len(self.events) - len(valid_events)} malformed events.")

        self.logger.info(f"[FRIDA] Returning {len(valid_events)} collected events.")
        self.logger.debug(f"[FRIDA] Sample event dump:\n{json.dumps(valid_events[:3], indent=2)}")
        return valid_events
