from pathlib import Path
from typing import List, Optional, Callable, Dict, Any
import time
import json

class FridaMultiHookManager:
    def __init__(
        self,
        session,
        script_paths: List[Path],
        logger,
        helpers_path: Optional[Path] = None,
        on_event_callback: Optional[Callable[[dict], None]] = None,
        message_timeout: int = 10
    ):
        self.session = session
        self.script_paths = script_paths
        self.logger = logger
        self.helpers_path = helpers_path
        self.on_event_callback = on_event_callback
        self.message_timeout = message_timeout

        self.events: List[Dict[str, Any]] = []
        self.hook_status: Dict[str, bool] = {}

    def _compose_script(self, script_path: Path) -> str:
        try:
            hook_code = script_path.read_text(encoding="utf-8")
        except Exception as ex:
            raise RuntimeError(f"Failed to read hook script {script_path}: {ex}")

        helpers_code = ""
        if self.helpers_path:
            try:
                helpers_code = self.helpers_path.read_text(encoding="utf-8")
            except Exception as ex:
                self.logger.warning(f"[FRIDA] Failed to read helpers from {self.helpers_path}: {ex}")

        return f"{helpers_code}\n\n// ---- Hook Script Begins ----\n\n{hook_code}"

    def _on_message(self, msg, data):
        if msg["type"] == "send":
            payload = msg.get("payload", {})
            if not isinstance(payload, dict):
                self.logger.warning(f"[FRIDA] Non-dict payload: {payload}")
                return

            # Ensure hook is present
            payload["hook"] = payload.get("hook") or "unknown"

            self.events.append(payload)
            self.logger.debug(f"[FRIDA EVENT][{payload['hook']}] {payload}")

            if self.on_event_callback:
                try:
                    self.on_event_callback(payload)
                except Exception as cb_err:
                    self.logger.warning(f"[FRIDA] on_event_callback error: {cb_err}")

        elif msg["type"] == "error":
            self.logger.error(f"[FRIDA ERROR] {msg.get('stack', msg)}")
        else:
            self.logger.debug(f"[FRIDA MESSAGE] {msg}")

    def _load_script(self, path: Path):
        try:
            full_code = self._compose_script(path)
            script = self.session.create_script(full_code)
            script.on("message", self._on_message)
            script.load()
            self.hook_status[path.name] = True
            self.logger.info(f"[FRIDA] Loaded hook: {path.name}")
        except Exception as ex:
            self.hook_status[path.name] = False
            self.logger.error(f"[FRIDA ERROR] Failed to load {path.name}: {ex}")
            self.logger.debug(f"[FRIDA DEBUG] Hook code from {path.name}:\n{full_code[:500]}...", exc_info=True)

    def load_all_hooks(self):
        self.logger.info(f"[FRIDA] Loading {len(self.script_paths)} hook scripts...")
        for path in self.script_paths:
            self._load_script(path)

        failed = [k for k, ok in self.hook_status.items() if not ok]
        if failed:
            self.logger.warning(f"[FRIDA] The following hooks failed to load: {failed}")

    def wait_for_activity(self, timeout: int = 10) -> bool:
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

        activity_detected = self.wait_for_activity(timeout=self.message_timeout)
        if not activity_detected:
            self.logger.warning("[FRIDA] No activity from any hook scripts.")

        if run_duration > 0:
            self.logger.debug(f"[FRIDA] Sleeping for {run_duration}s to collect runtime events...")
            time.sleep(run_duration)

        valid_events = [e for e in self.events if isinstance(e, dict)]
        if len(valid_events) != len(self.events):
            self.logger.warning(f"[FRIDA] Dropped {len(self.events) - len(valid_events)} malformed events.")

        self.logger.info(f"[FRIDA] Returning {len(valid_events)} collected events.")
        self.logger.debug(f"[FRIDA] Final event dump (up to 3): {json.dumps(valid_events[:3], indent=2)}")
        return valid_events
