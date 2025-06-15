import time
import frida

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

