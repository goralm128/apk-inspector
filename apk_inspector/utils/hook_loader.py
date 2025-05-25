from pathlib import Path

def load_hook_with_helpers(hook_path: Path, helpers_path: Path) -> str:
    """
    Combines frida_helpers.js with a specific hook script.
    Returns a single script string ready for Frida injection.
    """
    if not hook_path.exists():
        raise FileNotFoundError(f"Hook script not found: {hook_path}")
    if not helpers_path.exists():
        raise FileNotFoundError(f"Helpers script not found: {helpers_path}")

    with open(helpers_path, "r", encoding="utf-8") as helpers_file:
        helpers_code = helpers_file.read()

    with open(hook_path, "r", encoding="utf-8") as hook_file:
        hook_code = hook_file.read()

    return helpers_code + "\n\n// ---- Hook Script Begins ----\n\n" + hook_code
