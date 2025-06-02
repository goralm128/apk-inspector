import argparse
from pathlib import Path

def parse_args():
    parser = argparse.ArgumentParser(description="APK Inspector — Static + Dynamic Android Analyzer")

    parser.add_argument("--apk-dir", type=Path, default=Path("apks"),
                        help="Directory containing APK files to analyze")
    parser.add_argument("--output-dir", type=Path, default=Path("output"),
                        help="Directory to store analysis results and logs")
    parser.add_argument("--hooks-dir", type=Path, default=Path("frida/hooks"),
                        help="Directory containing Frida hook scripts")
    parser.add_argument("--include-private", action="store_true",
                        help="Include local/private IPs in dynamic analysis logs")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Timeout (seconds) per hook trace")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose logging to console and log file")
    parser.add_argument("--parallel", action="store_true",
                        help="Enable parallel processing of APKs")

    return parser.parse_args()

