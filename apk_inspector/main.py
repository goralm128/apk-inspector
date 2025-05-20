from apk_inspector.cli import parse_args
from apk_inspector.core import APKInspector, setup_logger
from apk_inspector.utils.hook_utils import discover_hooks
from pathlib import Path

def main():
    hooks_dir = Path(__file__).parent / "frida_hooks"
    hook_scripts = discover_hooks(hooks_dir)

    if not hook_scripts:
        raise FileNotFoundError(f"No Frida hook scripts found in {hooks_dir}")

    args = parse_args(hook_names=list(hook_scripts.keys()))
    logger = setup_logger(verbose=args.verbose)

    apk_dir = Path("apks")
    if not apk_dir.exists() or not any(apk_dir.glob("*.apk")):
        logger.warning("No APKs found in 'apks/' directory.")
        return

    inspector = APKInspector(
        hooks_dir=hooks_dir,
        apk_dir=apk_dir,
        output_file=Path("output/test_results.json"),
        logger=logger
    )

    inspector.run(
        hook_name=args.hook,
        include_private=args.include_private,
        timeout=args.timeout
    )

if __name__ == "__main__":
    main()
