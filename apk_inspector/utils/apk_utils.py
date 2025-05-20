import subprocess
import json
import re
from pathlib import Path
from typing import List, Optional

# ---------------- Optional: Androguard Import ----------------

try:
    from androguard.core.bytecodes.apk import APK  # type: ignore
    ANDROGUARD_AVAILABLE = True
except ImportError:
    APK = None
    ANDROGUARD_AVAILABLE = False
    print("[WARN] Androguard is not installed. Only `aapt` will be used for APK analysis.")

# ---------------- Package Name Extraction ----------------

def extract_package_name_from_filename(apk_path: Path) -> Optional[str]:
    """
    Try to extract the package name from filename (e.g., com.example.app_1.apk).
    """
    match = re.match(r"([a-zA-Z0-9_.]+)(?:_\d+)?\.apk", apk_path.name)
    return match.group(1) if match else None

def extract_package_name_aapt(apk_path: Path) -> Optional[str]:
    """
    Extracts the package name using the Android Asset Packaging Tool (aapt).
    """
    try:
        result = subprocess.run(
            ["aapt", "dump", "badging", str(apk_path)],
            capture_output=True,
            text=True,
            encoding="utf-8",      # ✅ Ensures proper decoding on Windows
            errors="replace",      # ✅ Prevents crash on UnicodeDecodeError
            check=True
        )

        if not result.stdout:
            print(f"[ERROR] aapt returned no output for {apk_path.name}")
            return None

        for line in result.stdout.splitlines():
            if line.startswith("package:"):
                for part in line.split():
                    if part.startswith("name="):
                        return part.split("=")[1].strip("'")
    except FileNotFoundError:
        print(f"[WARN] `aapt` not found. Trying Androguard for: {apk_path.name}")
    except subprocess.CalledProcessError as e:
        print(f"[WARN] aapt failed for {apk_path.name}: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error in aapt for {apk_path.name}: {e}")
    return None

def extract_package_name_androguard(apk_path: Path) -> Optional[str]:
    """
    Extracts the package name using Androguard (fallback).
    """
    if not ANDROGUARD_AVAILABLE:
        return None
    try:
        apk = APK(str(apk_path))
        return apk.get_package()
    except Exception as e:
        print(f"[WARN] Androguard failed for {apk_path.name}: {e}")
    return None

def get_package_name(apk_path: Path) -> Optional[str]:
    for extractor, label in [
        (extract_package_name_aapt, "aapt"),
        (extract_package_name_androguard, "Androguard"),
        (extract_package_name_from_filename, "filename fallback")
    ]:
        name = extractor(apk_path)
        if name:
            print(f"[✓] Package name from {label}: {name}")
            return name

    print(f"[ERROR] Could not extract package name for {apk_path.name}")
    return None


# ---------------- ADB Install/Uninstall Logic ----------------

def uninstall_package(package_name: str):
    print(f"[INFO] Uninstalling package: {package_name}")
    result = subprocess.run(["adb", "uninstall", package_name], capture_output=True, text=True)
    if "Success" in result.stdout:
        print(f"[✓] Uninstalled: {package_name}")
    else:
        print(f"[WARN] Failed to uninstall {package_name}: {result.stdout.strip()}")

def install_apks(folder_path: str) -> List[str]:
    """
    Installs all APKs in the folder and returns a list of installed package names.
    """
    apk_folder = Path(folder_path)
    apk_files = list(apk_folder.rglob("*.apk"))
    package_names = []

    if not apk_files:
        print(f"[WARN] No APK files found in {apk_folder.resolve()}")
        return []

    for apk in apk_files:
        pkg_name = get_package_name(apk)
        if not pkg_name:
            print(f"[WARN] Skipping {apk.name} — could not determine package name.")
            continue

        uninstall_package(pkg_name)

        print(f"[INFO] Installing APK: {apk.name}")
        result = subprocess.run(["adb", "install", str(apk.resolve())], capture_output=True, text=True)

        if result.returncode == 0 and "Success" in result.stdout:
            print(f"[✓] Installed: {apk.name}")
            package_names.append(pkg_name)
        else:
            print(f"[ERROR] Failed to install {apk.name}")
            print(f"stderr: {result.stderr.strip()}")
            print(f"stdout: {result.stdout.strip()}")

    return package_names

# ---------------- Save Analysis Results ----------------

def save_results(package_name: str, events: list, score: int = None,
                 verdict: str = None, yara_matches: list = None, reasons: list = None):
    """
    Saves events and optional metadata (score, verdict, reasons, YARA matches)
    for the specified package to a JSON file.
    Returns the path to the saved file.
    """
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    result_data = {
        "package": package_name,
        "events": events,
    }

    if score is not None:
        result_data["score"] = score
    if verdict:
        result_data["verdict"] = verdict
    if yara_matches:
        result_data["yara_matches"] = yara_matches
    if reasons:
        result_data["reasons"] = reasons

    output_path = output_dir / f"{package_name}.json"
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(result_data, f, indent=2, ensure_ascii=False)

    print(f"[✓] Results saved to {output_path.resolve()}")
    return output_path.resolve()

    """
    Saves events and optional metadata (score, verdict, YARA matches) for the specified package to a JSON file.
    Returns the path to the saved file.
    """
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    result_data = {
        "package": package_name,
        "events": events
    }

    if score is not None:
        result_data["score"] = score
    if verdict is not None:
        result_data["verdict"] = verdict
    if yara_matches:
        result_data["yara_matches"] = yara_matches

    output_path = output_dir / f"{package_name}.json"
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(result_data, f, indent=2, ensure_ascii=False)

    print(f"[✓] Results saved to {output_path.resolve()}")
    return output_path.resolve()

