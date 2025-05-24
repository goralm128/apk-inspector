from apk_inspector.utils.hook_utils import discover_hooks
from pathlib import Path
import pytest

def test_discovery():
    hook_dir = Path(__file__).parent.parent / "frida_hooks"

    if not hook_dir.exists():
        pytest.fail(f"[TEST ERROR] Hook directory does not exist at: {hook_dir.resolve()}")

    hooks = discover_hooks(hook_dir)

    assert isinstance(hooks, dict), "discover_hooks() did not return a dictionary"
    assert hooks, "No hooks found in frida_hooks directory"
    assert any(k in hooks for k in ["open", "network", "readwrite"]), "Expected at least one known hook"
