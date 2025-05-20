import sys
from pathlib import Path
import subprocess
import argparse
import shutil

# Add project root to PYTHONPATH
sys.path.append(str(Path(__file__).resolve().parent.parent))

from tools.generate_test_assets import main as generate_assets

SAMPLE_DIR = Path("tests/sample")

def clean():
    print("[*] Cleaning generated test data...")
    shutil.rmtree(SAMPLE_DIR / "decompiled", ignore_errors=True)
    shutil.rmtree(SAMPLE_DIR / "fake_apk_content", ignore_errors=True)
    (SAMPLE_DIR / "fake.apk").unlink(missing_ok=True)
    print("[✓] Cleanup complete.")

def test():
    print("[*] Setting up test data...")
    generate_assets()
    print("[*] Running tests...\n")
    subprocess.run(["pytest", "tests"], check=True)

def setup():
    print("[*] Setting up test data only...")
    generate_assets()

def main():
    parser = argparse.ArgumentParser(description="APK Inspector Dev Utility")
    parser.add_argument("action", choices=["setup", "test", "clean"], help="Action to perform")
    args = parser.parse_args()

    if args.action == "setup":
        setup()
    elif args.action == "test":
        test()
    elif args.action == "clean":
        clean()

if __name__ == "__main__":
    main()
