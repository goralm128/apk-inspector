import json
import re
from pathlib import Path
from typing import List

def extract_metadata(code: str) -> dict:
    """Extracts metadata object from a JS script, converting JS-like to JSON."""
    match = re.search(r"\bconst\s+metadata\s*=\s*({.*?})", code, re.DOTALL)
    if not match:
        return {}
    try:
        obj = match.group(1)
        # Fix keys without quotes: `key: value` → `"key": value`
        obj = re.sub(r'(\w+)\s*:', r'"\1":', obj)
        # Fix single to double quotes for strings
        obj = re.sub(r"'", r'"', obj)
        return json.loads(obj)
    except Exception:
        return {}

def validate_hook_script(script_path: Path) -> List[str]:
    """Validates a Frida JavaScript hook for completeness and compliance."""
    issues = []

    try:
        code = script_path.read_text(encoding="utf-8")
    except Exception as ex:
        return [f"Failed to read script: {ex}"]

    code = code.strip()
    if not code:
        return ["Script is empty."]

    metadata = extract_metadata(code)
    entrypoint = metadata.get("entrypoint", "").strip().lower()

    uses_java = any(kw in code for kw in [
        "Java.use(", "Java.perform(", "runWhenJavaIsReady(", "maybeRunJavaHook("])
    uses_native = "Interceptor.attach(" in code or "safeAttach(" in code

    # ─── Metadata checks ───
    if not entrypoint:
        issues.append("Missing 'entrypoint' in metadata.")

    if entrypoint == "java" and not uses_java:
        issues.append("Metadata entrypoint is 'java' but no Java APIs used.")

    if entrypoint == "native" and not uses_native:
        issues.append("Metadata entrypoint is 'native' but no native APIs used.")

    if not uses_java and not uses_native:
        issues.append("No Frida hooking logic found.")

    # ─── Emission logic ───
    emits_events = any(
        token in code
        for token in ["send(", "createHookLogger", "waitForLogger", "sendEvent", "log("]
    )
    if not emits_events:
        issues.append("No call to send() or logger — no events will be emitted.")

    if not re.search(r"\bhook\b\s*[:=]", code):
        issues.append("No `hook:` field defined in payloads — events may be uncategorized.")

    # ─── Anti-patterns ───
    if "module.exports" in code:
        issues.append("Contains Node.js export syntax.")

    if "require(" in code:
        issues.append("Contains Node.js require() call.")

    return issues
