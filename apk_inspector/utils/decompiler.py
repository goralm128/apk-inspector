import subprocess
from pathlib import Path

def decompile_apk(apk_path: Path, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Use ApkTool to get smali + manifest/resources
    apktool_cmd = ["apktool", "d", str(apk_path), "-o", str(output_dir), "-f"]
    subprocess.run(apktool_cmd, check=True)
    print(f"[✓] Decompiled with ApkTool: {output_dir}")

    return output_dir
