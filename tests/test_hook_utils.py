import os
import tempfile
from apk_inspector.utils.hook_utils import discover_hooks

def create_dummy_hooks(folder, names):
    for name in names:
        with open(os.path.join(folder, f"hook_{name}.js"), "w") as f:
            f.write("// dummy")

def test_discover_hooks():
    with tempfile.TemporaryDirectory() as temp_dir:
        dummy_hooks = ["network", "open", "readwrite"]
        create_dummy_hooks(temp_dir, dummy_hooks)

        result = discover_hooks(temp_dir)

        # Ensure all dummy hooks were discovered
        for hook in dummy_hooks:
            assert hook in result
            assert result[hook].endswith(f"hook_{hook}.js")

        # Ensure no unrelated files are picked up
        with open(os.path.join(temp_dir, "README.txt"), "w") as f:
            f.write("ignore me")
        result = discover_hooks(temp_dir)
        assert "README" not in result
