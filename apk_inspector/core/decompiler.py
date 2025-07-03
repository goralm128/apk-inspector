import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple, List,TYPE_CHECKING
from collections import Counter
from lxml import etree
import logging
import os
import zipfile


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

def is_safe_path(root: Path, target: Path) -> bool:
    try:
        return root.resolve(strict=False) in target.resolve(strict=False).parents or root.resolve() == target.resolve()
    except Exception:
        return False

def safe_write_text(path: Path, content: str, label: str = ""):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        logger.info(f"[Androguard] Wrote text: {path} {label}")
    except Exception as e:
        logger.warning(f"[Androguard] Failed to write text file {path.name}: {e} {label}")

def safe_write_bytes(path: Path, content: bytes, label: str = ""):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        logger.info(f"[Androguard] Wrote binary: {path} ({len(content)} bytes) {label}")
    except Exception as e:
        logger.warning(f"[Androguard] Failed to write binary file {path.name}: {e} {label}")

def analyze_apk_with_androguard(apk_path: Path, output_dir: Path) -> Tuple[Path, str, "APK"]:
    """
    Fully extract an APK using Androguard and ZIP fallback.

    Returns:
        Tuple:
            - Path to output directory
            - Backend used: "androguard"
            - APK object
    """
    logger.info(f"[Androguard] Starting analysis: {apk_path}")
    apk_obj, _, _ = AnalyzeAPK(str(apk_path))
    ext_counter = Counter()

    # --- AndroidManifest.xml ---
    manifest_xml = apk_obj.get_android_manifest_xml()
    if manifest_xml is not None:
        xml_str = etree.tostring(manifest_xml, pretty_print=True, encoding="unicode")
        safe_write_text(output_dir / "AndroidManifest.xml", xml_str, label="(AndroidManifest)")
    else:
        logger.warning("[Androguard] Failed to extract AndroidManifest.xml")

    # --- Package Info ---
    package_info = (
        f"Package: {apk_obj.package}\n"
        f"Main Activity: {apk_obj.get_main_activity()}\n"
        f"Permissions: {apk_obj.get_permissions()}\n"
    )
    safe_write_text(output_dir / "package_info.txt", package_info, label="(metadata)")

    # --- DEX Files ---
    try:
        dex_files = apk_obj.get_all_dex()
        if not dex_files:
            logger.warning("[Androguard] No DEX files returned by get_all_dex()")
            with apk_path.open("rb") as f:
                if b'dex\n035' in f.read():
                    logger.warning("[Androguard] DEX header found in raw APK, but not returned")
        for idx, dex in enumerate(dex_files):
            name = f"classes{'' if idx == 0 else idx+1}.dex"
            path = output_dir / name
            safe_write_bytes(path, dex, label="(DEX)")
            ext_counter[".dex"] += 1
    except Exception as e:
        logger.error(f"[Androguard] Exception extracting DEX: {e}")

    # --- Files via get_files() ---
    try:
        files = apk_obj.get_files()
        logger.info(f"[Androguard] get_files() returned: {type(files)}, items: {len(files) if hasattr(files, '__len__') else '?'}")

        entries = files.items() if isinstance(files, dict) else files if isinstance(files, list) else []
        for entry in entries:
            if isinstance(entry, tuple) and len(entry) == 2:
                name, content = entry
                path = output_dir / name
                if not is_safe_path(output_dir, path):
                    logger.warning(f"[Androguard] Skipped unsafe path: {path}")
                    continue
                safe_write_bytes(path, content, label="(file)")
                ext_counter[Path(name).suffix.lower()] += 1
    except Exception as e:
        logger.warning(f"[Androguard] Error during get_files(): {e}")

    # --- ZIP Fallback to ensure complete coverage ---
    try:
        with zipfile.ZipFile(apk_path, 'r') as zipf:
            for entry in zipf.infolist():
                zip_path = output_dir / entry.filename
                if zip_path.exists():
                    continue  # Already handled
                if not is_safe_path(output_dir, zip_path):
                    logger.warning(f"[ZIP] Unsafe path skipped: {zip_path}")
                    continue
                try:
                    zip_path.parent.mkdir(parents=True, exist_ok=True)
                    with zipf.open(entry) as src, zip_path.open('wb') as dst:
                        data = src.read()
                        if data:
                            dst.write(data)
                            ext_counter[Path(entry.filename).suffix.lower()] += 1
                            logger.debug(f"[ZIP] Extracted: {zip_path} ({len(data)} bytes)")
                except Exception as e:
                    logger.warning(f"[ZIP] Failed extracting {entry.filename}: {e}")
    except Exception as e:
        logger.error(f"[ZIP] ZIP-level fallback failed: {e}")

    # --- Extraction Summary ---
    logger.info(f"[Androguard] Extraction summary for {apk_path.name}:")
    total_files = sum(ext_counter.values()) + 2  # +2 for manifest and package info
    logger.info(f"[Androguard] - Total files: {total_files}")
    for ext, count in ext_counter.most_common():
        logger.info(f"[Androguard] - {ext or '[no extension]'}: {count} file(s)")

    return output_dir, "androguard", apk_obj