import subprocess
import shutil
from pathlib import Path

def decompile_apk(apk_path: Path, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    apktool_path = shutil.which("apktool")
    if not apktool_path:
        raise FileNotFoundError("`apktool` not found in PATH. Make sure it's installed and available.")

    apktool_cmd = f'"{apktool_path}" d "{apk_path}" -o "{output_dir}" -f'
    
    subprocess.run(apktool_cmd, shell=True, check=True)
    print(f"[✓] Decompiled with ApkTool: {output_dir}")

    return output_dir
