import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from apk_inspector.core.apk_manager import APKManager


@pytest.fixture
def apk_manager():
    return APKManager(logger=None)


def test_extract_package_name_from_filename():
    from apk_inspector.utils.apk_utils import extract_package_name_from_filename
    path = Path("com.example.app_1.apk")
    assert extract_package_name_from_filename(path) == "com.example.app"


@patch("apk_inspector.core.apk_manager.subprocess.run")
def test_install_apk_success(mock_run, tmp_path, apk_manager):
    # Setup
    apk_path = tmp_path / "dummy.apk"
    apk_path.write_text("fake content")

    # Mocks
    apk_manager.get_package_name = lambda x: "com.example.app"
    mock_run.return_value = MagicMock(returncode=0, stdout="Success")

    result = apk_manager.install_apk(apk_path)
    assert result is True


@patch("apk_inspector.core.apk_manager.subprocess.run")
def test_install_apk_failure(mock_run, tmp_path, apk_manager):
    apk_path = tmp_path / "bad.apk"
    apk_path.write_text("bad content")

    apk_manager.get_package_name = lambda x: "com.bad.app"
    mock_run.return_value = MagicMock(returncode=1, stdout="Failure")

    result = apk_manager.install_apk(apk_path)
    assert result is False


def test_get_package_name_fallback(monkeypatch, apk_manager):
    path = Path("com.fallback.test_123.apk")

    monkeypatch.setattr(apk_manager, "extract_package_name_aapt", lambda p: None)
    monkeypatch.setattr(apk_manager, "extract_package_name_androguard", lambda p: None)

    name = apk_manager.get_package_name(path)
    assert name == "com.fallback.test"
