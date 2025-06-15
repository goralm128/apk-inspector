import subprocess
import time
import re
from pathlib import Path
from lxml import etree
from apk_inspector.utils.logger import get_logger
from apk_inspector.utils.apk_utils import get_apk_path_from_package_name, normalize_activity

logger = get_logger()
AAPT_EXE = "aapt"

# ─────────── Device Status Checks ───────────

def is_device_connected():
    try:
        return subprocess.check_output(["adb", "get-state"]).decode().strip() == "device"
    except Exception:
        logger.error("[ADB] No device connected or ADB not available.")
        return False

def is_rooted():
    try:
        result = subprocess.check_output(["adb", "shell", "su", "-c", "id"], stderr=subprocess.DEVNULL).decode()
        return "uid=0" in result
    except Exception:
        logger.error("[ADB] Device is not rooted or su command failed.")
        return False

def is_frida_server_running():
    try:
        return "frida-server" in subprocess.check_output(["adb", "shell", "ps"]).decode()
    except Exception:
        logger.error("[ADB] Failed to check frida-server.")
        return False

def get_device_arch():
    try:
        return subprocess.check_output(["adb", "shell", "getprop", "ro.product.cpu.abi"]).decode().strip()
    except Exception:
        logger.error("[ADB] Failed to get architecture.")
        return None

def check_device_compatibility():
    if not is_device_connected():
        raise RuntimeError("No Android device connected via ADB.")
    if not is_rooted():
        raise RuntimeError("Device is not rooted.")
    if not is_frida_server_running():
        raise RuntimeError("frida-server is not running.")
    arch = get_device_arch()
    if arch not in ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]:
        raise RuntimeError(f"Unsupported device architecture: {arch}")
    logger.info(f"Device compatible. Architecture: {arch}")

# ─────────── App Lifecycle ───────────

def wake_and_unlock():
    try:
        subprocess.run(["adb", "shell", "input", "keyevent", "KEYCODE_WAKEUP"], check=True)
        subprocess.run(["adb", "shell", "input", "keyevent", "KEYCODE_MENU"], check=True)
        subprocess.run(["adb", "shell", "wm", "dismiss-keyguard"], check=True)
        logger.info("[ADB] Wake/unlock sequence completed.")
    except Exception as ex:
        logger.error(f"[ADB] Failed to wake/unlock: {ex}")

def extract_main_activity(apk_path: Path) -> str:
    output = subprocess.check_output([AAPT_EXE, "dump", "badging", str(apk_path)])
    for line in output.decode().splitlines():
        match = re.search(r"launchable-activity: name='([^']+)'", line)
        if match:
            return match.group(1)
    raise RuntimeError("No launchable activity found")

def launch_main_activity(package_name: str, run_dir: Path, logger) -> str | None:
    apk_path = get_apk_path_from_package_name(package_name)
    if not apk_path or not apk_path.exists():
        logger.warning(f"[AAPT] Could not find APK for package: {package_name}")
    try:
        activity = extract_main_activity(apk_path)
        # Only normalize if '/' not present (to avoid doubling)
        activity = normalize_activity(package_name, activity)
        logger.info(f"[AAPT] Found main activity: {activity}")
        return activity
    except Exception as e:
        logger.warning(f"[AAPT] Could not determine main activity: {e}")
        
    manifest_path = run_dir / "decompiled" / package_name / "AndroidManifest.xml"
    try:
        tree = etree.parse(str(manifest_path))
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        for activity in tree.xpath("//activity", namespaces=ns):
            for intent_filter in activity.xpath("intent-filter", namespaces=ns):
                actions = intent_filter.xpath("action[@android:name='android.intent.action.MAIN']", namespaces=ns)
                categories = intent_filter.xpath("category[@android:name='android.intent.category.LAUNCHER']", namespaces=ns)
                if actions and categories:
                    name = activity.get(f"{{{ns['android']}}}name")
                    if name:
                        full = f"{package_name}.{name}" if not name.startswith(package_name) else name
                        logger.info(f"[Manifest] Found main activity: {full}")
                        return full
    except Exception as e:
        logger.error(f"[Manifest] Failed to parse manifest: {e}")
    return None

def launch_app_direct(package: str, activity: str, logger, timeout=10) -> bool:
    logger.info(f"[ADB] Launching: {package}/{activity}")
    try:
        subprocess.run(["adb", "shell", "am", "start", "-n", f"{package}/{activity}"],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        logger.error(f"[ADB] Launch failed: {e.stderr.decode().strip()}")
        return False

    start = time.time()
    while time.time() - start < timeout:
        logcat = subprocess.run(["adb", "logcat", "-d"], capture_output=True, text=True)
        if "ActivityManager: START" in logcat.stdout and package in logcat.stdout:
            logger.info("[ADB] Launch confirmed.")
            return True
        time.sleep(0.5)

    logger.warning("[ADB] Launch not confirmed.")
    return False

def force_stop_app(package_name):
    try:
        subprocess.run(["adb", "shell", "am", "force-stop", package_name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except Exception as ex:
        logger.error(f"[ADB] Failed to stop app: {ex}")

def install_apks(apk_dir: Path):
    packages = []
    for apk_path in apk_dir.glob("*.apk"):
        try:
            output = subprocess.check_output(["aapt", "dump", "badging", str(apk_path)], stderr=subprocess.DEVNULL).decode()
            match = re.search(r"package: name='([^']+)'", output)
            if not match:
                logger.warning(f"[ADB] No package name in {apk_path.name}")
                continue
            pkg = match.group(1)
            subprocess.run(["adb", "uninstall", pkg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["adb", "install", str(apk_path)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info(f"[ADB] Installed {apk_path.name} ({pkg})")
            packages.append(pkg)
        except Exception as e:
            logger.error(f"[ADB] Failed to install {apk_path.name}: {e}")
    return packages
