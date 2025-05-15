import argparse
from pathlib import Path
from apk_inspector.core import APKInspector

def parse_args(hooks_dir: Path) -> argparse.Namespace:
    """
    Parses command-line arguments for the APK Inspector.

    :param hooks_dir: Path to the directory containing Frida hook scripts.
    :return: Parsed arguments namespace.
    """
    # Initialize inspector to retrieve available hook names dynamically
    inspector = APKInspector(hooks_dir, apk_dir=None, output_file=None)
    
    parser = argparse.ArgumentParser(description="APK Inspector")
    parser.add_argument(
        "--hook",
        required=True,
        choices=list(inspector.hook_scripts.keys()),
        help="Choose which Frida hook to run"
    )
    parser.add_argument(
        "--include-private",
        action="store_true",
        help="Include local/private network traffic in output (for network hook)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Number of seconds to trace each app (default: 10)"
    )
    
    return parser.parse_args()
