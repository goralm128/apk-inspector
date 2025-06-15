from pathlib import Path
import re
from typing import Optional
import subprocess

def extract_package_name_from_filename(apk_path: Path) -> Optional[str]:
    match = re.match(r"([a-zA-Z0-9_.]+)(?:_\d+)?\.apk", apk_path.name)
    return match.group(1) if match else None

def get_apk_path_from_package_name(package_name: str, apk_dir: Path = Path("apks")) -> Path | None:
    for apk in apk_dir.glob("*.apk"):
        try:
            output = subprocess.check_output(["aapt", "dump", "badging", str(apk)], stderr=subprocess.DEVNULL).decode()
            match = re.search(r"package: name='([^']+)'", output)
            if match and match.group(1) == package_name:
                return apk
        except Exception:
            continue
    return None

def normalize_activity(package_name: str, activity: str) -> str:
    if activity.startswith("."):
        return f"{package_name}{activity}"
    return activity




