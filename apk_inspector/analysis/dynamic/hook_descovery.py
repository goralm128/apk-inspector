import json
import re
from pathlib import Path
from typing import Dict, Optional

from apk_inspector.analysis.dynamic.hook_validator import validate_hook_script

def extract_metadata_from_hook(script_path: Path) -> Optional[Dict]:
    """
    Parses the `const metadata = { ... }` or `const metadata_<hook> = { ... }` block from a Frida hook file.
    Handles JS-style syntax with unquoted keys, booleans, single quotes, and comments.
    """
    try:
        text = script_path.read_text(encoding="utf-8")

        # Match metadata declaration
        match = re.search(r'(?:const|var|let)\s+metadata(?:_\w+)?\s*=\s*{(.*?)};', text, re.DOTALL)
        if not match:
            return None

        block = match.group(1)

        # JS to JSON normalization
        block = re.sub(r'//.*', '', block)  # Remove line comments
        block = re.sub(r'/\*.*?\*/', '', block, flags=re.DOTALL)  # Remove block comments
        block = re.sub(r'(\w+)\s*:', r'"\1":', block)  # Quote keys
        block = block.replace("'", '"')  # Normalize single quotes
        block = re.sub(r',\s*}', '}', block)  # Remove trailing commas

        block = "{" + block.strip() + "}"
        return json.loads(block)

    except Exception as ex:
        print(f"[!] Failed to parse metadata from {script_path.name}: {ex}")
        return None

def discover_hooks(hook_dir: Path, logger, filter_tags: Optional[list] = None, only_sensitive: bool = False) -> Dict[str, Dict]:
    """
    Discover and validate Frida hook scripts.
    Returns dict: hook_name -> { path, metadata }
    """
    hooks = {}
    for path in hook_dir.glob("hook_*.js"):
        logger.debug(f"[✓] Found potential hook file: {path.name}")
        hook_name = path.stem.replace("hook_", "")

        # Validate the hook
        #issues = validate_hook_script(path)
        #if issues:
        #    if logger:
        #        logger.warning(f"[!] Hook '{hook_name}' skipped due to validation errors:")
        #        for issue in issues:
        #            logger.warning(f"    - {issue}")
        #    continue

        metadata = extract_metadata_from_hook(path) or {}
        if not metadata:
            logger.warning(f"[!] Hook '{hook_name}' skipped: failed to extract metadata.")
            continue
        metadata.setdefault("name", hook_name)

        # Optional filtering
        if only_sensitive and not metadata.get("sensitive"):
            continue
        if filter_tags:
            tags = metadata.get("tags", [])
            if not any(tag in tags for tag in filter_tags):
                continue

        hooks[hook_name] = {
            "path": path,
            "metadata": metadata
        }

    return hooks
