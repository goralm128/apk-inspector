import sys
from apk_inspector.cli.cli import parse_args
from apk_inspector.utils.fs_utils import ensure_dirs_exist
from apk_inspector.utils.logger import init_logging
from apk_inspector.utils.workspace_utils import create_run_directory
from apk_inspector.core.apk_batch_runner import APKBatchRunner
from apk_inspector.reports.report_saver import ReportSaver
from apk_inspector.reports.report_manager import ReportManager
from pathlib import Path


def configure_logging(run_dir: Path, verbose: bool):
    log_path = run_dir / "full.log"
    logger = init_logging(verbose=verbose, log_path=log_path)
    logger.info("[✓] Logger initialized.")
    return logger

def initialize_batch_runner(args, apk_paths, run_dir) -> APKBatchRunner:
    report_saver = ReportSaver(run_dir=run_dir)
    report_manager = ReportManager(report_saver=report_saver)
    
    return APKBatchRunner(
        apk_paths=apk_paths,
        hooks_dir=args.hooks_dir,
        report_manager=report_manager,
        timeout=args.timeout,
        include_private=args.include_private,
        parallel=args.parallel
    )

def run_analysis():
    args = parse_args()

    # Step 1: Validate input/output dirs
    ensure_dirs_exist([args.apk_dir, args.output_dir, args.hooks_dir])

    apk_paths = sorted(args.apk_dir.glob("*.apk"))
    if not apk_paths:
        print(f"[ERROR] No APKs found in: {args.apk_dir}", file=sys.stderr)
        return 1

    if not args.hooks_dir.is_dir():
        print(f"[ERROR] Hooks directory does not exist: {args.hooks_dir}", file=sys.stderr)
        return 1

    # Step 2: Prepare run folder and logger
    run_dir, _ = create_run_directory(args.output_dir)
    logger = configure_logging(run_dir, verbose=args.verbose)

    # Step 3: Start analysis
    logger.info(f"[*] Starting APK analysis in {'parallel' if args.parallel else 'serial'} mode...")

    runner = initialize_batch_runner(args, apk_paths, run_dir)
    try:
        runner.run()
    except Exception as ex:
        logger.error(f"[✗] Batch analysis fatal error: {ex}", exc_info=True)    

    return 0


def main():
    """
    Main entry point for running APK analysis.
    Validates directories, prepares logging, and runs the batch analysis.
    Returns 0 on success, 1 on error.
    """
    try:
        sys.exit(run_analysis())
    except Exception as ex:
        print(f"[ERROR] {type(ex).__name__}: {ex}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
