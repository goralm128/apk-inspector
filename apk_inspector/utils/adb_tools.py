import subprocess

# ───────────────────────────────────────────────────────────────
# Device Connectivity and Compatibility Checks
# ───────────────────────────────────────────────────────────────

def is_device_connected():
    """Checks if an Android device is connected via ADB."""
    try:
        output = subprocess.check_output(["adb", "get-state"]).decode().strip()
        return output == "device"
    except Exception:
        return False


def is_rooted():
    """Checks if the device has root access (required for Frida)."""
    try:
        result = subprocess.check_output(["adb", "shell", "su", "-c", "id"], stderr=subprocess.DEVNULL).decode()
        return "uid=0" in result
    except Exception:
        return False


def is_frida_server_running():
    """Checks if frida-server is running on the device."""
    try:
        output = subprocess.check_output(["adb", "shell", "ps"]).decode()
        return "frida-server" in output
    except Exception:
        return False


def get_device_arch():
    """Gets the device architecture (e.g., arm64-v8a, x86)."""
    try:
        arch = subprocess.check_output(["adb", "shell", "getprop", "ro.product.cpu.abi"]).decode().strip()
        return arch
    except Exception:
        return None


def check_device_compatibility():
    """Runs a full check for ADB connection, root access, Frida, and architecture support."""
    print("[*] Checking device compatibility...")

    if not is_device_connected():
        raise RuntimeError("❌ No Android device connected via ADB.")

    if not is_rooted():
        raise RuntimeError("❌ Device is not rooted. Root access is required for Frida to attach.")

    if not is_frida_server_running():
        raise RuntimeError("❌ frida-server is not running on the device. Please start it manually.")

    arch = get_device_arch()
    if arch not in ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]:
        raise RuntimeError(f"❌ Unsupported device architecture: {arch}")

    print(f"[✓] Device is ready. Architecture: {arch}")


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
        print(f"[WARN] Failed to wake/unlock device: {e}")


def launch_app(package_name):
    """Launches an Android app by its package name using monkey tool."""
    try:
        subprocess.run([
            "adb", "shell", "monkey", "-p", package_name,
            "-c", "android.intent.category.LAUNCHER", "1"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except Exception as e:
        print(f"[WARN] Failed to launch app {package_name}: {e}")


def force_stop_app(package_name):
    """Stops a running Android app forcefully."""
    try:
        subprocess.run(["adb", "shell", "am", "force-stop", package_name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except Exception as e:
        print(f"[WARN] Failed to stop app {package_name}: {e}")
