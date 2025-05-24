from pathlib import Path
import re
from typing import Optional

def extract_package_name_from_filename(apk_path: Path) -> Optional[str]:
    match = re.match(r"([a-zA-Z0-9_.]+)(?:_\d+)?\.apk", apk_path.name)
    return match.group(1) if match else None
