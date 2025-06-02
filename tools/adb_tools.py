import subprocess
from pathlib import Path
import time
from apk_inspector.utils.logger import get_logger

logger = get_logger()

# ───────────────────────────────────────────────────────────────
# Device Connectivity and Compatibility Checks
# ───────────────────────────────────────────────────────────────

def is_device_connected():
    """Checks if an Android device is connected via ADB."""
    try:
        output = subprocess.check_output(["adb", "get-state"]).decode().strip()
        return output == "device"
    except Exception:
        logger.error("[ADB] No device connected or ADB not available.")
        return False


def is_rooted():
    """Checks if the device has root access (required for Frida)."""
    try:
        result = subprocess.check_output(["adb", "shell", "su", "-c", "id"], stderr=subprocess.DEVNULL).decode()
        return "uid=0" in result
    except Exception:
        logger.error("[ADB] Device is not rooted or su command failed.")
        return False


def is_frida_server_running():
    """Checks if frida-server is running on the device."""
    try:
        output = subprocess.check_output(["adb", "shell", "ps"]).decode()
        return "frida-server" in output
    except Exception:
        logger.error("[ADB] Failed to check if frida-server is running.")
        return False


def get_device_arch():
    """Gets the device architecture (e.g., arm64-v8a, x86)."""
    try:
        arch = subprocess.check_output(["adb", "shell", "getprop", "ro.product.cpu.abi"]).decode().strip()
        return arch
    except Exception:
        logger.error("[ADB] Failed to get device architecture.")
        return None


def check_device_compatibility():
    """Runs a full check for ADB connection, root access, Frida, and architecture support."""
    print("[*] Checking device compatibility...")

    if not is_device_connected():
        raise RuntimeError("No Android device connected via ADB.")

    if not is_rooted():
        raise RuntimeError("Device is not rooted. Root access is required for Frida to attach.")

    if not is_frida_server_running():
        raise RuntimeError("frida-server is not running on the device. Please start it manually.")

    arch = get_device_arch()
    if arch not in ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]:
        raise RuntimeError(f"Unsupported device architecture: {arch}")

    logger.info(f"Device compatibility check passed. Architecture: {arch}")


# ───────────────────────────────────────────────────────────────
# App Lifecycle Operations
# ───────────────────────────────────────────────────────────────

def wake_and_unlock():
    """Wakes and unlocks the device via ADB shell commands."""
    try:
        subprocess.run(["adb", "shell", "input", "keyevent", "KEYCODE_WAKEUP"], check=True)
        subprocess.run(["adb", "shell", "input", "keyevent", "KEYCODE_MENU"], check=True)
        subprocess.run(["adb", "shell", "wm", "dismiss-keyguard"], check=True)
        print("[✓] Device wake/unlock sequence completed.")
    except Exception as e:
        logger.error(f"[ADB] Failed to wake/unlock device: {e}")
     
def launch_app_direct(package: str, activity: str, logger, timeout=10) -> bool:
    logger.info(f"[ADB] Trying to start {package}/{activity}")
    cmd = ["adb", "shell", "am", "start", "-n", f"{package}/{activity}"]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        logger.error(f"[ADB] Failed to launch activity: {e.stderr.decode().strip()}")
        return False

    start = time.time()
    while time.time() - start < timeout:
        logcat = subprocess.run(["adb", "logcat", "-d"], capture_output=True, text=True)
        if f"ActivityManager: START" in logcat.stdout and package in logcat.stdout:
            logger.info(f"[ADB] Launch confirmed for: {package}")
            return True
        time.sleep(0.5)

    logger.warning(f"[ADB] Launch of {package} not confirmed after {timeout}s")
    return False

def force_stop_app(package_name):
    """Stops a running Android app forcefully."""
    try:
        subprocess.run(["adb", "shell", "am", "force-stop", package_name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except Exception as e:
        logger.error(f"[ADB] Failed to stop app {package_name}: {e}")


def install_apks(apk_dir: Path):
    """
    Installs all APKs in the given directory. Returns list of detected package names.
    """
    import re
    packages = []

    for apk_path in Path(apk_dir).glob("*.apk"):
        try:
            # Extract package name using aapt
            result = subprocess.check_output(["aapt", "dump", "badging", str(apk_path)], stderr=subprocess.DEVNULL).decode("utf-8")
            match = re.search(r"package: name='([^']+)'", result)
            if not match:
                logger.warning(f"[ADB] Could not extract package name from {apk_path.name}")
                continue

            pkg_name = match.group(1)
            logger.info(f"[ADB] Package name from aapt: {pkg_name}")

            # Uninstall and reinstall
            subprocess.run(["adb", "uninstall", pkg_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["adb", "install", str(apk_path)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info(f"[ADB] Installed {apk_path.name} with package name {pkg_name}")
            packages.append(pkg_name)

        except subprocess.CalledProcessError as e:
            logger.error(f"[ADB] Error installing {apk_path.name}: {e}")
        except Exception as e:
            logger.error(f"[ADB] Unexpected error with {apk_path.name}: {e}")
          
    return packages



