from pathlib import Path
from typing import Iterable

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
