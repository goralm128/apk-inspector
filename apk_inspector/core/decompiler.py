import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple, TYPE_CHECKING, Union
from lxml import etree
import logging
import os

# Conditional import only for type hints
if TYPE_CHECKING:
    from androguard.core.bytecodes.apk import APK

try:
    from androguard.misc import AnalyzeAPK
    HAS_ANDROGUARD = True
except ImportError:
    HAS_ANDROGUARD = False

logger = logging.getLogger(__name__)


def decompile_apk(apk_path: Path, output_dir: Path) -> Tuple[Path, str, Optional["APK"]]:
    """
    Attempt to decompile an APK using Androguard (preferred) or ApkTool (fallback).

    Returns:
        Tuple:
            - Path to the decompiled output directory
            - Backend used: "androguard" or "apktool"
            - APK object (only if using Androguard, otherwise None)
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    if HAS_ANDROGUARD:
        try:
            logger.info(f"Using Androguard to analyze APK: {apk_path}")
            return analyze_apk_with_androguard(apk_path, output_dir)
        except Exception as e:
            logger.warning(f"Androguard failed: {e}. Falling back to ApkTool...")

    logger.warning("Falling back to ApkTool for decompilation.")
    apktool_path = shutil.which("apktool")
    if not apktool_path:
        raise FileNotFoundError("Neither Androguard is available nor `apktool` found in PATH.")

    apktool_cmd = [apktool_path, "d", str(apk_path), "-o", str(output_dir), "-f"]
    logger.info(f"Running ApkTool: {' '.join(apktool_cmd)}")

    try:
        result = subprocess.run(
            apktool_cmd,
            check=True,
            capture_output=True,
            text=True,
            shell=os.name == "nt"  # shell=True only on Windows
        )
        logger.debug(result.stdout)
        logger.debug(result.stderr)
        logger.info(f"Decompiled successfully using ApkTool: {output_dir}")
        return output_dir, "apktool", None
    except subprocess.CalledProcessError as e:
        logger.error(f"ApkTool failed with exit code {e.returncode}")
        logger.error(e.stderr)
        raise


def analyze_apk_with_androguard(apk_path: Path, output_dir: Path) -> Tuple[Path, str, "APK"]:
    """
    Analyze an APK file using Androguard and extract key files to the output directory.

    Returns:
        Tuple: (decompiled_dir, "androguard", APK object)
    """
    a, d, dx = AnalyzeAPK(str(apk_path))

    # Save AndroidManifest.xml
    manifest_path = output_dir / "AndroidManifest.xml"
    manifest_xml = a.get_android_manifest_xml()
    if manifest_xml is not None:
        manifest_path.write_text(
            etree.tostring(manifest_xml, pretty_print=True, encoding="unicode"),
            encoding="utf-8"
        )

    # Save package metadata
    (output_dir / "package_info.txt").write_text(
        f"Package: {a.package}\n"
        f"Main Activity: {a.get_main_activity()}\n"
        f"Permissions: {a.get_permissions()}\n",
        encoding="utf-8"
    )

    # Save DEX files for further analysis or YARA scanning
    for idx, dex in enumerate(a.get_all_dex()):
        dex_path = output_dir / f"classes{'' if idx == 0 else idx + 1}.dex"
        dex_path.write_bytes(dex)

    # Save assets/files — some YARA rules look for payloads or hidden scripts
    files = a.get_files()
    if isinstance(files, dict):  # Older API
        iterable = files.items()
    elif isinstance(files, list):  # Newer API
        iterable = files
    else:
        iterable = []

    for entry in iterable:
        try:
            if isinstance(entry, tuple) and len(entry) == 2:
                name, content = entry
                target = output_dir / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
        except Exception as ex:
            logger.warning(f"[Androguard] Failed to extract file entry: {ex}")

    logger.info(f"Androguard analysis completed successfully: {output_dir}")
    return output_dir, "androguard", a
