from pathlib import Path
from typing import List

def validate_hook_script(script_path: Path) -> List[str]:
    issues = []
    try:
        code = script_path.read_text(encoding="utf-8")
    except Exception as ex:
        return [f"Failed to read script: {ex}"]

    stripped_code = code.strip()
    if not stripped_code:
        issues.append("Script is empty.")
        return issues

    if not any(e in code for e in ["Interceptor.attach(", "Java.perform(", "runWhenJavaIsReady("]):
        issues.append("Missing Frida entrypoint (Interceptor.attach or Java.perform or runWhenJavaIsReady).")

    if "send(" not in code and "createHookLogger" not in code:
        issues.append("No call to send() or usage of createHookLogger — no events will be emitted.")

    if "hook:" not in code and "hook : " not in code:
        issues.append("No `hook:` field in log payloads. Events may be uncategorized.")

    if "module.exports" in code:
        issues.append("Contains Node.js syntax `module.exports`.")

    if "require(" in code:
        issues.append("Contains Node.js-like `require()`.")

    return issues
