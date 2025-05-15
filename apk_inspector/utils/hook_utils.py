from pathlib import Path

def discover_hooks(hook_dir):
    """
    Scans the given directory for Frida hook scripts matching 'hook_*.js' pattern.
    Returns a dict mapping hook names (e.g., 'open') to script paths.
    """
    hook_scripts = {}
    hook_path = Path(hook_dir).resolve()

    if not hook_path.exists():
        raise FileNotFoundError(f"Hook directory not found: {hook_path}")

    for path in hook_path.glob("hook_*.js"):
        name = path.stem.replace("hook_", "")
        hook_scripts[name] = str(path)

    return hook_scripts
