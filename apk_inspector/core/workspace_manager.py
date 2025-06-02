
from pathlib import Path
from datetime import datetime
from typing import Optional

class WorkspaceManager:
    """
    Manages directory structure for analysis, including consistent decompiled paths.
    """

    def __init__(self, run_dir: Optional[Path] = None, base_dir: Optional[Path] = None, timestamp: Optional[str] = None):
        if run_dir:
            self.run_dir = run_dir
            self.timestamp = run_dir.name
        else:
            self.timestamp = timestamp or datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            assert base_dir is not None, "base_dir is required if run_dir is not provided"
            self.run_dir = base_dir / self.timestamp
            self.run_dir.mkdir(parents=True, exist_ok=True)

    def get_run_dir(self) -> Path:
        return self.run_dir

    def get_decompile_path(self, package_name: str, apk_path: Optional[Path] = None, create: bool = False) -> Path:
        preferred = self.run_dir / "decompiled" / package_name
        if preferred.exists():
            return preferred

        if apk_path:
            fallback = self.run_dir / "decompiled" / apk_path.stem
            if fallback.exists():
                return fallback

        if create:
            preferred.mkdir(parents=True, exist_ok=True)

        return preferred

    def create_decompile_dir(self, package_name: str) -> Path:
        path = self.run_dir / "decompiled" / package_name
        path.mkdir(parents=True, exist_ok=True)
        return path

    def ensure_subdir(self, name: str) -> Path:
        path = self.run_dir / name
        path.mkdir(parents=True, exist_ok=True)
        return path
