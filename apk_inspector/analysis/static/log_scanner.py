import re
from pathlib import Path
from apk_inspector.utils.logger import get_logger

LOGGING_PATTERNS = [
    r'Log\.d\s*\(\s*".*?"\s*,\s*".*?"\s*\)',  # Log.d("TAG", "message")
    r'Log\.i\s*\(\s*".*?"\s*,\s*".*?"\s*\)',
    r'Log\.e\s*\(\s*".*?"\s*,\s*".*?"\s*\)',
    r'System\.out\.println\s*\(.*?\)',        # println()
]

SENSITIVE_HINTS = [
    "password", "passwd", "pwd",
    "secret", "api_key", "token",
    "auth", "jwt", "bearer"
]

logger = get_logger()

def scan_logs_for_secrets(decompiled_dir: Path) -> list:
    results = []

    skipped_dirs = {"lib", "res", "original", "assets", "META-INF"}
    skipped_exts = {".png", ".jpg", ".gif", ".webp", ".so", ".mp3", ".mp4", ".xml", ".json"}

    for file in decompiled_dir.rglob("*.smali"):
        try:
            relative_path = file.relative_to(decompiled_dir)
            rel_path_str = str(relative_path).replace("\\", "/")  # Normalize for Windows paths

            # --- Skip smali/kotlin paths ---
            if "smali/kotlin/" in rel_path_str:
                logger.debug(f"Skipping Kotlin standard file: {relative_path}")
                continue

            # Skip top-level known irrelevant folders
            top_dir = relative_path.parts[0] if relative_path.parts else ""
            if top_dir in skipped_dirs:
                logger.debug(f"Skipping file in skipped dir '{top_dir}': {relative_path}")
                continue

            if file.suffix.lower() in skipped_exts:
                logger.debug(f"Skipping file by extension: {relative_path}")
                continue

            content = file.read_text(errors="ignore").lower()
            for line in content.splitlines():
                if any(p in line for p in ["log", "println"]):
                    for hint in SENSITIVE_HINTS:
                        if hint in line:
                            results.append({
                                "file": str(relative_path),
                                "line": line.strip(),
                                "hint": hint
                            })

        except Exception as ex:
            logger.warning(f"[logscan] Error scanning file {file}: {ex}")

    logger.info(f"[logscan] Found {len(results)} potential log leaks.")
    return results
