import sys
from apk_inspector.cli.cli import parse_args
from apk_inspector.utils.fs_utils import ensure_dirs_exist
from apk_inspector.runner.apk_runner import APKBatchRunner
from apk_inspector.reports.report_saver import ReportSaver

def main():
    try:
        args = parse_args()
        ensure_dirs_exist([args.apk_dir, args.output_dir, args.hooks_dir])

        # Collect APKs
        apk_paths = sorted(args.apk_dir.glob("*.apk"))
        if not apk_paths:
            print(f"[WARNING] No APKs found in: {args.apk_dir}", file=sys.stderr)
            sys.exit(0)

        # Create ReportSaver
        report_saver = ReportSaver(output_root=args.output_dir)

        # Launch batch runner
        runner = APKBatchRunner(
            apk_paths=apk_paths,
            hooks_dir=args.hooks_dir,
            report_saver=report_saver,
            timeout=args.timeout,
            include_private=args.include_private,
            parallel=args.parallel
        )
        runner.run()

    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

