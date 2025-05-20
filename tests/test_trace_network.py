import logging
from pathlib import Path
from unittest.mock import patch
from apk_inspector.core import APKInspector
from apk_inspector.utils.rule_engine import Verdict


@patch("apk_inspector.core.RuleEngine.evaluate")
@patch("apk_inspector.core.trace_frida_events")
@patch("apk_inspector.core.install_apks")
@patch("apk_inspector.core.save_results")
def test_run_analysis_network_hook_includes_private_ips(mock_save, mock_install, mock_trace, mock_eval):
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

    # 👇 Ensure rule evaluation doesn't crash
    mock_eval.return_value = Verdict(score=7, label="suspicious", reasons=["network communication"])

    logger = logging.getLogger("test_logger")
    logger.addHandler(logging.NullHandler())

    inspector = APKInspector(
        hooks_dir=Path("apk_inspector/frida_hooks"),
        apk_dir=Path("apks"),
        output_file=Path("output/test_results.json"),
        logger=logger
    )

    inspector.run("network", include_private=True, timeout=5)

    # Ensure save_results was called
    assert mock_save.call_count > 0, "save_results was not called."

    # Check keyword arguments instead of positional
    _, kwargs = mock_save.call_args
    events_arg = kwargs.get("events")

    assert isinstance(events_arg, list), f"Expected list of events, got: {type(events_arg)}"
    assert len(events_arg) == 2, f"Expected 2 events, got: {len(events_arg)}"
    assert {"ip": "192.168.1.100"} in [e["address"] for e in events_arg]
    assert {"ip": "8.8.8.8"} in [e["address"] for e in events_arg]

