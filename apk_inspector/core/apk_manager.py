import subprocess
import re
from pathlib import Path
from typing import List, Optional

from apk_inspector.utils.apk_utils import extract_package_name_from_filename


# Safe Androguard import wrapper
try:
    from androguard.core.bytecodes.apk import APK  # type: ignore
    ANDROGUARD_AVAILABLE = True
except ModuleNotFoundError:
    ANDROGUARD_AVAILABLE = False
    APK = None  # type: ignore

class APKManager:
    _installed_cache = set()  # Track installed packages per session
    """
    Manages APK metadata extraction and install/uninstall operations via ADB.
    """

    def __init__(self, logger=None):
        self.logger = logger
        if not ANDROGUARD_AVAILABLE and self.logger:
            self.logger.warning("[WARN] Androguard is not installed. Only `aapt` will be used.")

    def get_package_name(self, apk_path: Path) -> Optional[str]:
        for extractor, label in [
            (self.extract_package_name_aapt, "aapt"),
            (self.extract_package_name_androguard, "Androguard"),
            (extract_package_name_from_filename, "filename fallback")
        ]:
            name = extractor(apk_path)
            if name:
                if self.logger:
                    self.logger.debug(f"[✓] Package name from {label}: {name}")
                return name
        if self.logger:
            self.logger.warning(f"[✗] Could not extract package name for {apk_path.name}")
        return None

    def extract_package_name_aapt(self, apk_path: Path) -> Optional[str]:
        try:
            result = subprocess.run(
                ["aapt", "dump", "badging", str(apk_path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=True
            )
            for line in result.stdout.splitlines():
                if line.startswith("package:"):
                    for part in line.split():
                        if part.startswith("name="):
                            return part.split("=")[1].strip("'")
        except Exception as ex:
            if self.logger:
                self.logger.warning(f"[WARN] aapt failed: {ex}")
        return None

    def extract_package_name_androguard(self, apk_path: Path) -> Optional[str]:
        if not ANDROGUARD_AVAILABLE or APK is None:
            return None
        try:
            apk = APK(str(apk_path))
            return apk.get_package()
        except Exception as ex:
            if self.logger:
                self.logger.warning(f"[WARN] Androguard failed for {apk_path.name}: {ex}")
        return None

    def uninstall_package(self, package_name: str):
        if self.logger:
            self.logger.info(f"[INFO] Uninstalling: {package_name}")
        subprocess.run(["adb", "uninstall", package_name], capture_output=True, text=True)

    def install_apk(self, apk_path: Path, package_name: Optional[str] = None) -> bool:
        if not package_name:
            package_name = self.get_package_name(apk_path)
        if not package_name:
            if self.logger:
                self.logger.warning(f"[WARN] Could not determine package name for {apk_path.name}")
            return False

        if package_name in APKManager._installed_cache:
            if self.logger:
                self.logger.info(f"[✓] {package_name} is already installed. Skipping reinstall.")
            APKManager._installed_cache.add(package_name)
            return True
        if not package_name:
            package_name = self.get_package_name(apk_path)
        if not package_name:
            if self.logger:
                self.logger.warning(f"[WARN] Could not determine package name for {apk_path.name}")
            return False

        self.uninstall_package(package_name)

        if self.logger:
            self.logger.info(f"[INFO] Installing APK: {apk_path.name}")
        result = subprocess.run(
            ["adb", "install", str(apk_path.resolve())],
            capture_output=True,
            text=True
        )

        if result.returncode == 0 and "Success" in result.stdout:
            if self.logger:
                self.logger.info(f"[✓] Installed: {apk_path.name}")
            return True
        else:
            if self.logger:
                self.logger.error(f"[✗] Failed to install {apk_path.name}: {result.stdout.strip()}")
            return False

    def install_apks_in_dir(self, apk_dir: Path) -> List[str]:
        """
        Installs all APKs in the directory and returns list of installed package names.
        """
        apk_files = list(apk_dir.rglob("*.apk"))
        if self.logger and not apk_files:
            self.logger.warning(f"[!] No APKs found in {apk_dir.resolve()}")

        package_names = []
        for apk in apk_files:
            pkg_name = self.get_package_name(apk)
            if not pkg_name:
                continue
            if self.install_apk(apk, pkg_name):
                package_names.append(pkg_name)

        return package_names
