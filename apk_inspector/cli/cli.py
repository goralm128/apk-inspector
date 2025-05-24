import argparse
from pathlib import Path

def parse_args():
    parser = argparse.ArgumentParser(description="APK Inspector — Static + Dynamic Android Analyzer")

    parser.add_argument("--apk-dir", type=Path, default=Path("apks"),
                        help="Directory containing APK files")
    parser.add_argument("--output-dir", type=Path, default=Path("output"),
                        help="Directory to store output results")
    parser.add_argument("--hooks-dir", type=Path, default=Path("frida_hooks"),
                        help="Directory of Frida hook scripts (e.g., frida_hooks/)")
    parser.add_argument("--include-private", action="store_true",
                        help="Include private/local IP addresses in network logs")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Trace duration per app per hook (in seconds)")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose logging")
    parser.add_argument("--parallel", action="store_true",
                        help="Run APK analysis in parallel")

    return parser.parse_args()
