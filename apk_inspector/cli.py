import argparse
from typing import List

def parse_args(hook_names: List[str]) -> argparse.Namespace:
    """
    Parses command-line arguments for APK Inspector.

    :param hook_names: A list of valid Frida hook names to use as choices.
    :return: Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(description="APK Inspector")

    parser.add_argument(
        "--hook",
        required=True,
        choices=hook_names,
        help="Choose which Frida hook to run"
    )

    parser.add_argument(
        "--apk-dir",
        type=str,
        default="apks",
        help="Path to directory containing APK files (default: ./apks)"
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default="output",
        help="Path to store output files (default: ./output)"
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

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    return parser.parse_args()
