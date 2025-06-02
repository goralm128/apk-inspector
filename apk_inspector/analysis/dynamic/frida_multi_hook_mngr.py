from pathlib import Path
from typing import List, Optional
import time

class FridaMultiHookManager:
    def __init__(self, session, script_paths: List[Path], logger, on_event_callback=None, message_timeout=5, helpers_path: Optional[Path] = None):
        self.session = session
        self.script_paths = [Path(p) for p in script_paths]
        self.logger = logger
        self.on_event_callback = on_event_callback
        self.message_timeout = message_timeout
        self.helpers_path = helpers_path
        self.events = []
    def _load_script(self, script_path: Path):
        try:
            helpers_code = self.helpers_path.read_text(encoding="utf-8")
            hook_code = script_path.read_text(encoding="utf-8")
            full_code = helpers_code + "\n\n" + hook_code

            script = self.session.create_script(full_code)

            def on_message(msg, data):
                if msg["type"] == "send":
                    payload = msg.get("payload", {})
                    self.logger.debug(f"[FRIDA EVENT] {payload}")
                    self.events.append(payload)
                    if self.on_event_callback:
                        self.on_event_callback(payload)
                elif msg["type"] == "error":
                    self.logger.error(f"[FRIDA ERROR] {msg.get('stack', msg)}")

            script.on("message", on_message)
            script.load()
            self.logger.info(f"[FRIDA] Loaded hook: {script_path.name}")
        except Exception as e:
            self.logger.warning(f"[FRIDA] Error loading hook {script_path}: {e}")

    def load_all_hooks(self):
        for path in self.script_paths:
            try:
                self._load_script(path)
            except Exception as e:
                self.logger.warning(f"[FRIDA] Failed to load hook {path.name}: {e}")

    def wait_for_activity(self, timeout=10):
        self.logger.info(f"[FRIDA] Waiting up to {timeout}s for hook activity...")
        start = time.time()
        while (time.time() - start) < timeout:
            if self.events:
                return True
            time.sleep(0.5)
        self.logger.warning("[FRIDA] No hook activity detected in timeout window.")
        return False

    def run(self, run_duration=10):
        self.load_all_hooks()
        self.wait_for_activity(timeout=self.message_timeout)
        time.sleep(run_duration)
        return self.events
