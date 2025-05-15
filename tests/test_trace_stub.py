import json
from pathlib import Path
from unittest.mock import patch
from apk_inspector.core import APKInspector

@patch("apk_inspector.core.trace_frida_events")
@patch("apk_inspector.core.install_apks")
@patch("apk_inspector.core.save_results")  #  needed to prevent actual file saves
def test_run_analysis_open_hook_creates_expected_json(mock_save, mock_install, mock_trace):
    mock_install.return_value = ["com.example.fakeapp"]
    mock_trace.return_value = [
        {"event": "file_opened", "path": "/data/data/com.example.fakeapp/files/config.json"}
    ]

    test_output_file = Path("output/test_results.json")
    if test_output_file.exists():
        test_output_file.unlink()  # ensure clean slate

    inspector = APKInspector(
        hooks_dir=Path("apk_inspector/frida_hooks"),
        apk_dir=Path("apks"),
        output_file=test_output_file
    )

    inspector.run("open", include_private=False, timeout=5)

    # Validate the output file
    assert test_output_file.exists(), "Output JSON file was not created"

    with open(test_output_file, "r", encoding="utf-8") as f:
        results = json.load(f)

    assert isinstance(results, list)
    assert results[0]["package"] == "com.example.fakeapp"
    assert results[0]["events"] == mock_trace.return_value

    # Cleanup
    test_output_file.unlink()