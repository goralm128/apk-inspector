import asyncio
import time
from pathlib import Path
import frida


class FridaSession:
    
    def __init__(self, device, package_name, logger):
        self.device = device
        self.package_name = package_name
        self.logger = logger
        self.session = None
        self.pid = None
        self.spawn_gating_enabled = False

    def spawn_and_attach(self):
        try:
            self.pid = self.device.spawn([self.package_name])
            self.session = self.device.attach(self.pid)
            self.logger.info(f"[FRIDA] Spawned and attached to PID {self.pid}")
        except frida.ProcessNotFoundError:
            self.logger.error(f"[FRIDA] Package not found or failed to spawn: {self.package_name}")
            raise
        except Exception as e:
            self.logger.exception(f"[FRIDA] Failed to spawn and attach: {e}")
            raise

    def resume(self):
        try:
            self.device.resume(self.pid)
            self.logger.info(f"[FRIDA] Resumed PID {self.pid}")
        except Exception as e:
            self.logger.warning(f"[FRIDA] Failed to resume PID {self.pid}: {e}")

    def is_alive(self):
        try:
            return any(p.pid == self.pid for p in self.device.enumerate_processes())
        except Exception:
            return False

    def load_script(self, script_code: str, on_message=None):
        try:
            script = self.session.create_script(script_code)
            if on_message:
                script.on("message", on_message)
            script.load()
            self.logger.info(f"[FRIDA] ✅ Loaded script from raw string")
            return script
        except Exception as e:
            self.logger.error(f"[FRIDA] ❌ Failed to load script: {e}")
            raise

    def load_script_from_file(self, path: Path, on_message=None):
        """
        Loads a Frida script from file and returns the script object.
        """
        try:
            code = path.read_text(encoding="utf-8")
            return self.load_script(code, on_message=on_message)
        except Exception as e:
            self.logger.error(f"[FRIDA] ❌ Failed to load script from {path.name}: {e}")
            raise

    def detach(self):
        try:
            if self.session:
                self.session.detach()
                self.logger.debug("[FRIDA] Detached session.")
        except frida.InvalidOperationError:
            self.logger.debug("[FRIDA] Session already detached.")
        except Exception as e:
            self.logger.warning(f"[FRIDA] Detach failed: {e}")

    def kill(self):
        try:
            if self.pid:
                self.device.kill(self.pid)
                self.logger.debug(f"[FRIDA] Killed PID {self.pid}")
        except Exception as e:
            self.logger.warning(f"[FRIDA] Kill failed: {e}")

    def cleanup(self, kill_process=True):
        """
        Gracefully detaches from the process and optionally kills it.
        """
        self.logger.debug("[FRIDA] Cleaning up session...")
        self.detach()
        if kill_process:
            self.kill()

    async def wait_for_java_vm(self, probe_path: str, timeout: int = 30):
        """
        Injects a script to wait for Java.perform to succeed.
        """
        self.logger.info("[FRIDA] Waiting for Java VM readiness...")

        if not self.is_alive():
            self.logger.warning("[FRIDA] App crashed before Java VM could initialize.")
            return False

        try:
            probe_code = Path(probe_path).read_text(encoding="utf-8")
            script = self.session.create_script(probe_code)
            script.on("message", lambda msg, data: self.logger.debug(f"[vm_probe] {msg}"))
            script.load()

            try:
                await asyncio.wait_for(script.exports.wait(), timeout=timeout)
                self.logger.info("[FRIDA] ✅ Java VM is ready.")
                return True
            except asyncio.TimeoutError:
                self.logger.warning("[FRIDA] ❌ Java VM wait timed out.")
                return False
            except frida.InvalidOperationError as e:
                self.logger.warning(f"[FRIDA] ❌ Java VM probe script error: {e}")
                return False
            except AttributeError:
                self.logger.error("[FRIDA] ❌ Probe script missing `exports.wait()`")
                return False
            finally:
                try:
                    script.unload()
                except Exception as e:
                    self.logger.debug(f"[FRIDA] Could not unload probe script: {e}")
        except Exception as e:
            self.logger.warning(f"[FRIDA] Failed to inject vm_probe.js: {e}")
            return False

    def load_and_wait_for_signal(self, path: Path, signal_type="ready", timeout=30):
        """
        Loads a script and blocks until a specific `send({ type })` is received.
        """
        loop = asyncio.get_event_loop()
        future = loop.create_future()

        def on_msg(msg, data):
            if msg.get("type") == "send":
                payload = msg.get("payload", {})
                if isinstance(payload, dict) and payload.get("type") == signal_type:
                    future.set_result(payload)

        try:
            script = self.load_script_from_file(path, on_message=on_msg)
            loop.run_until_complete(asyncio.wait_for(future, timeout=timeout))
            self.logger.info(f"[FRIDA] Received signal: {signal_type}")
            script.unload()
            return future.result()
        except asyncio.TimeoutError:
            self.logger.warning(f"[FRIDA] Timed out waiting for signal: {signal_type}")
            return None
        except Exception as e:
            self.logger.error(f"[FRIDA] Error waiting for signal: {e}")
            return None

    def enable_spawn_gating(self, hook_manager=None, java_hook_paths=None, timeout=45):
        """
        Enable spawn gating and queue Java hooks into forked child processes after JVM readiness.

        :param hook_manager: Optional FridaMultiHookManager instance
        :param java_hook_paths: Optional list of Path to Java-only hook files
        :param timeout: Timeout in seconds to wait for JVM signal
        """
        self.logger.info("[FRIDA] ✅ Spawn gating enabled")
        
        self.spawn_gating_enabled = True

        def on_spawn(spawn):
            name = spawn.identifier
            self.logger.info(f"[SPAWN] ➕ New spawn: {name} (PID={spawn.pid})")

            if self.package_name not in name:
                self.logger.debug(f"[SPAWN] Ignored unrelated spawn: {name}")
                return

            try:
                self.device.resume(spawn.pid)
                time.sleep(0.75)
                child_session = self.device.attach(spawn.pid)
                self.logger.info(f"[SPAWN] ✅ Attached to child PID: {spawn.pid}")

                self._load_vm_probe_and_hooks(
                    session=child_session,
                    pid=spawn.pid,
                    hook_manager=hook_manager,
                    java_hook_paths=java_hook_paths,
                    timeout=timeout
                )
            except Exception as e:
                self.logger.warning(f"[SPAWN] ❌ Failed to attach/load to child PID {spawn.pid}: {e}")

        self.device.on("spawn-added", on_spawn)
        self.device.enable_spawn_gating()
        
    def disable_spawn_gating(self):
        if not getattr(self, "spawn_gating_enabled", False):
            return
        try:
            self.device.disable_spawn_gating()
            self.logger.info("[FRIDA] Spawn gating disabled")
        except Exception as e:
            self.logger.warning(f"[FRIDA] Failed to disable spawn gating: {e}")
        finally:
            # Always mark as disabled to prevent future attempts
            self.spawn_gating_enabled = False

    def _load_vm_probe_and_hooks(self, session, pid, hook_manager=None, java_hook_paths=None, timeout=45):
        """
        Inject vm_probe.js and queue Java hooks into a specific session once JVM is ready.
        """
        try:
            vm_probe_code = Path("frida/helpers/vm_probe.js").read_text(encoding="utf-8")
        except Exception as e:
            self.logger.error(f"[SPAWN] Failed to read vm_probe.js: {e}")
            return

        try:
            script = session.create_script(vm_probe_code)
        except Exception as e:
            self.logger.error(f"[SPAWN] Failed to create vm_probe script: {e}")
            return

        loop = asyncio.get_event_loop()
        future = loop.create_future()

        def on_message(msg, data):
            self.logger.debug(f"[SPAWN] [vm_probe] {msg}")
            if msg.get("type") == "send" and msg["payload"].get("type") == "jvm_ready":
                self.logger.info(f"[SPAWN] ✅ Child JVM ready (PID={pid})")
                future.set_result(True)

        script.on("message", on_message)

        try:
            script.load()
        except Exception as e:
            self.logger.error(f"[SPAWN] Failed to load vm_probe.js into PID {pid}: {e}")
            return

        try:
            loop.run_until_complete(asyncio.wait_for(future, timeout=timeout))
        except asyncio.TimeoutError:
            self.logger.warning(f"[SPAWN] ❌ JVM wait timed out for PID {pid}")
        except Exception as e:
            self.logger.warning(f"[SPAWN] JVM wait failed: {e}")
        finally:
            try:
                script.unload()
            except Exception:
                pass

        # Load Java hooks
        if java_hook_paths:
            for path in java_hook_paths:
                try:
                    code = path.read_text(encoding="utf-8")
                    hook_script = session.create_script(code)
                    hook_script.load()
                    self.logger.info(f"[SPAWN] ✅ Java hook loaded: {path.name}")
                except Exception as e:
                    self.logger.warning(f"[SPAWN] ❌ Failed to load {path.name}: {e}")

        elif hook_manager:
            try:
                hook_manager.load_java_hooks()
                self.logger.info(f"[SPAWN] ✅ Java hooks injected by hook manager")
            except Exception as e:
                self.logger.error(f"[SPAWN] Hook manager error: {e}")

