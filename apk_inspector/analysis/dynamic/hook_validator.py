from pathlib import Path
from typing import List
import re
import json

def extract_metadata(code: str) -> dict:
    """Extract metadata object from JavaScript source if defined."""
    match = re.search(r"const\s+metadata\s*=\s*{.*?}", code, re.DOTALL)
    if match:
        obj_str = match.group(0).split("=", 1)[-1].strip().rstrip(";")
        try:
            # Replace JS-style keys without quotes with JSON-compatible format
            json_like = re.sub(r"(\w+):", r'"\1":', obj_str)
            return json.loads(json_like)
        except Exception:
            return {}
    return {}

def validate_hook_script(script_path: Path) -> List[str]:
    issues = []
    try:
        code = script_path.read_text(encoding="utf-8")
    except Exception as ex:
        return [f"Failed to read script: {ex}"]

    stripped_code = code.strip()
    if not stripped_code:
        return ["Script is empty."]

    metadata = extract_metadata(code)
    entrypoint = metadata.get("entrypoint", "").strip().lower()

    # Validate entrypoint classification
    uses_java = any(kw in code for kw in ["Java.use(", "Java.perform(", "runWhenJavaIsReady("])
    uses_native = "Interceptor.attach(" in code or "safeAttach(" in code

    if not entrypoint:
        issues.append("Missing 'entrypoint' in metadata.")

    if entrypoint == "java" and not uses_java:
        issues.append("Metadata entrypoint is 'java' but no Java APIs found.")

    if entrypoint == "native" and not uses_native:
        issues.append("Metadata entrypoint is 'native' but no native hooks (e.g. Interceptor.attach) found.")

    if not uses_java and not uses_native:
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