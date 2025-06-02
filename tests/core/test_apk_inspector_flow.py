from apk_inspector.core.apk_inspector import APKInspector
from apk_inspector.core.apk_manager import APKManager
from apk_inspector.reports.report_saver import ReportSaver
import logging
from pathlib import Path


def test_run_full_analysis_on_fake_apk(tmp_path):
    apk_path = Path("sample/fake.apk")
    hooks_dir = Path("frida_hooks")  # should point to .js hooks
    output_file = tmp_path / "combined_output.json"

    # Create core dependencies
    logger = logging.getLogger("APKInspectorTest")
    logger.setLevel(logging.DEBUG)
    apk_manager = APKManager()
    report_saver = ReportSaver()

    # Create inspector
    inspector = APKInspector(
        hooks_dir=hooks_dir,
        apk_dir=apk_path.parent,
        output_file=output_file,
        logger=logger,
        report_saver=report_saver,
        apk_manager=apk_manager,
    )

    result = inspector.run_full_analysis_for_apk(
        apk_path=apk_path,
        timeout=2,
        include_private=False
    )

    assert result["package"]
    assert isinstance(result["events"], list)
    assert isinstance(result["yara_matches"], list)
    assert isinstance(result["static_analysis"], dict)
    assert result["verdict"] in {"benign", "suspicious", "malicious", "error"}

    print("[✓] Full analysis test passed on fake.apk")
