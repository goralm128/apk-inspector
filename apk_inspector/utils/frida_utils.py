import time
import frida

def wait_for_process(device, package: str, timeout: int = 10) -> int:
    """
    Waits for the given package to appear in the process list.
    Returns the PID when found, or raises ProcessNotFoundError after timeout.
    """
    for _ in range(timeout * 2):  # Check every 0.5s
        try:
            return device.get_process(package).pid
        except frida.ProcessNotFoundError:
            time.sleep(0.5)
    raise frida.ProcessNotFoundError(f"App '{package}' not found after {timeout}s")
