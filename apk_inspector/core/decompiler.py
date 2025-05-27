import shutil
import subprocess
from pathlib import Path

def decompile_apk(apk_path: Path, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    apktool_path = shutil.which("apktool")
    if not apktool_path:
        raise FileNotFoundError("`apktool` not found in PATH. Make sure it's installed.")

    apktool_cmd = f'"{apktool_path}" d "{apk_path}" -o "{output_dir}" -f'
    print(f"[INFO] Running ApkTool: {apktool_cmd}")

    try:
        subprocess.run(apktool_cmd, shell=True, check=True)
        print(f"[✓] Decompiled successfully: {output_dir}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] ApkTool failed for {apk_path}: {e}")
        raise

    return output_dir
