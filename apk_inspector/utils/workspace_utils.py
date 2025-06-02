from pathlib import Path
from datetime import datetime
from typing import Tuple

def create_run_directory(output_root: Path, timestamp: str = None) -> Tuple[Path, str]:
    """
    Creates a timestamped run directory under the output root.

    Returns:
        Tuple[Path, str]: (Path to run directory, timestamp string)
    """
    timestamp = timestamp or datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = output_root / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)
    
    return run_dir, timestamp
