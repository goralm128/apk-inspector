from pathlib import Path
from typing import Iterable
from typing import Dict, Optional, Any

def ensure_dirs_exist(dirs: Iterable[Path]) -> None:
    """
    Ensure each path in `dirs` exists. If a directory does not exist, it will be created.

    Args:
        dirs (Iterable[Path]): A list or iterable of Path objects.
    """
    for directory in dirs:
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise RuntimeError(f"Failed to create directory '{directory}': {e}")

def extract_file_path(event: Dict[str, Any]) -> Optional[str]:
    return event.get("path") or event.get("file") or event.get("filename")
