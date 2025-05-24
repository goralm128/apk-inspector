import pytest
from pathlib import Path
from unittest.mock import MagicMock

from apk_inspector.core.core_controller import APKInspector
from apk_inspector.core.apk_manager import APKManager
from apk_inspector.reports.report_saver import ReportSaver


@pytest.fixture
def fake_apk_inspector(tmp_path):
    logger = MagicMock()
    apk_dir = tmp_path / "apks"
    hooks_dir = tmp_path / "hooks"
    output_file = tmp_path / "output.json"
    apk_dir.mkdir()
    hooks_dir.mkdir()

    report_saver = ReportSaver(output_dir=tmp_path, logger=logger)
    apk_manager = APKManager(logger=logger)

    # You can mock apk_manager.install_apks_in_dir if needed
    apk_manager.install_apks_in_dir = MagicMock(return_value=["com.example.app"])

    return APKInspector(
        hooks_dir=hooks_dir,
        apk_dir=apk_dir,
        output_file=output_file,
        logger=logger,
        report_saver=report_saver,
        apk_manager=apk_manager
    )


def test_initialization(fake_apk_inspector):
    assert fake_apk_inspector is not None
    assert isinstance(fake_apk_inspector.installed_packages, list)


def test_trace_package_handles_no_device(fake_apk_inspector):
    fake_apk_inspector.static_cache["com.example.app"] = ([], {})
    result = fake_apk_inspector.trace_package(
        package="com.example.app",
        script="dummy",
        hook_name="network",
        include_private=False,
        timeout=5
    )

    assert result["verdict"] in ["error", "benign", "suspicious", "malicious"]
