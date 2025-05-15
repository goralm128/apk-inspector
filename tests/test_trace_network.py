from pathlib import Path
from unittest.mock import patch
from apk_inspector.core import APKInspector

@patch("apk_inspector.core.trace_frida_events")
@patch("apk_inspector.core.install_apks")
@patch("apk_inspector.core.save_results")
def test_run_analysis_network_hook_includes_private_ips(mock_save, mock_install, mock_trace):
    mock_install.return_value = ["com.example.networkapp"]
    mock_trace.return_value = [
        {
            "event": "sendto",
            "fd": 12,
            "address": {"ip": "192.168.1.100"},
            "data": "Hello internal",
            "length": 15
        },
        {
            "event": "sendto",
            "fd": 13,
            "address": {"ip": "8.8.8.8"},
            "data": "Hello Google",
            "length": 13
        }
    ]

    # Create inspector with dummy paths
    inspector = APKInspector(
        hooks_dir=Path("apk_inspector/frida_hooks"),
        apk_dir=Path("apks"),
        output_file=Path("output/test_results.json")
    )

    # Run with include_private=True, so both events should be kept
    inspector.run("network", include_private=True, timeout=5)

    args, kwargs = mock_save.call_args
    saved_events = args[1]

    assert len(saved_events) == 2
    assert {"ip": "192.168.1.100"} in [e["address"] for e in saved_events]
    assert {"ip": "8.8.8.8"} in [e["address"] for e in saved_events]
