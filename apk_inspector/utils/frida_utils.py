import asyncio
import time
import frida

async def wait_for_java_vm(session, logger, timeout=30):
    script = session.create_script("""
        rpc.exports = {
            wait: function () {
                return new Promise((resolve, reject) => {
                    let attempts = 0;
                    let maxAttempts = 60;
                    let interval = 500;

                    function tryCheck() {
                        if (typeof Java === 'undefined') {
                            attempts++;
                            if (attempts >= maxAttempts) return reject("Java is not defined");
                            return setTimeout(tryCheck, interval);
                        }

                        if (!Java.available) {
                            attempts++;
                            if (attempts >= maxAttempts) return reject("Java not available");
                            return setTimeout(tryCheck, interval);
                        }

                        try {
                            Java.perform(() => {
                                resolve(true);
                            });
                        } catch (e) {
                            reject(e);
                        }
                    }

                    tryCheck();
                });
            }
        };
    """)
    logger.debug("[FRIDA] Injecting Java VM polling script...")
    script.on("message", lambda msg, _: logger.debug(f"[wait_for_java_vm] {msg}"))
    script.load()

    try:
        result = await asyncio.wait_for(script.exports.wait(), timeout=timeout)
        logger.info("[FRIDA] Java VM is ready.")
        script.unload()
        return True
    except Exception as e:
        logger.warning(f"[wait_for_java_vm] Gave up waiting for Java VM: {e}")
        script.unload()
        return False


def wait_for_process(device, package: str, timeout: int = 20, interval: float = 0.5, logger=None) -> int:
    """
    Waits for the given package to appear in the process list.
    Returns the PID when found, or raises ProcessNotFoundError after timeout.

    :param device: frida.Device instance
    :param package: The app package name to wait for
    :param timeout: Total timeout in seconds
    :param interval: Polling interval in seconds
    :param logger: Optional logger for debug output
    :return: PID of the process
    """
    start_time = time.time()
    deadline = start_time + timeout

    while time.time() < deadline:
        try:
            pid = device.get_process(package).pid
            if logger:
                logger.debug(f"[wait_for_process] Found {package} with PID {pid}")
            return pid
        except frida.ProcessNotFoundError:
            if logger:
                logger.debug(f"[wait_for_process] {package} not found yet, retrying...")
            time.sleep(interval)

    elapsed = round(time.time() - start_time, 2)
    message = f"App '{package}' not found after {elapsed}s"
    if logger:
        logger.error(f"[wait_for_process] {message}")
    raise frida.ProcessNotFoundError(message)


def get_usb_device_safe(logger, retries=3, delay=2):
    for attempt in range(retries):
        try:
            return frida.get_usb_device(timeout=2000)
        except frida.InvalidOperationError as e:
            logger.warning(f"[FRIDA] Device manager closed (attempt {attempt+1}/{retries}): {e}")
        except Exception as e:
            logger.warning(f"[FRIDA] Error accessing USB device (attempt {attempt+1}/{retries}): {e}")
        time.sleep(delay)
    raise RuntimeError("Unable to acquire USB device. Frida device manager may be shut down.")
