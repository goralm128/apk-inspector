from apk_inspector.cli import parse_args
from apk_inspector.core import APKInspector
from pathlib import Path

def main():
    hooks_dir = Path(__file__).parent / "frida_hooks"
    args = parse_args(hooks_dir)

    inspector = APKInspector(
        hooks_dir=hooks_dir,
        apk_dir=Path("apks"),
        output_file=Path("output/results.json")
    )
    inspector.run(args.hook, include_private=args.include_private, timeout=args.timeout)

if __name__ == "__main__":
    main()
# This script is the entry point for the APK Inspector tool. It initializes the APKInspector class with the specified hook directory, APK directory, and output file, and then runs the analysis based on command-line arguments.