from pathlib import Path
from typing import List

def validate_hook_script(script_path: Path) -> List[str]:
    """
    Validates a Frida hook script for common issues.
    Returns a list of error messages (empty if no issues).
    """
    issues = []

    try:
        code = script_path.read_text(encoding="utf-8")
    except Exception as e:
        return [f"Failed to read script: {e}"]

    stripped_code = code.strip()

    # Empty script
    if not stripped_code:
        issues.append("Script is empty.")
        return issues

    # Frida entrypoint detection
    if "Interceptor.attach" not in code and "Java.perform" not in code:
        issues.append("Missing Frida entrypoint (`Interceptor.attach` or `Java.perform`).")

    # Event emission detection
    if "send(" not in code and "createHookLogger" not in code:
        issues.append("No `send()` call or `createHookLogger()` detected. No data will be sent back to Python.")

    # Incompatible Node.js patterns
    if "module.exports" in code:
        issues.append("Contains Node.js syntax `module.exports` which is invalid in Frida.")

    if "require(" in code:
        issues.append("Use of `require()` suggests Node.js code; not compatible with Frida.")

    return issues
