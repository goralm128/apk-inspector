#!/usr/bin/env python3
import re
from pathlib import Path

HOOKS_DIR = Path("frida/hooks")
HOOK_PATTERN = re.compile(r"^hook_\w+\.js$")

LOGGER_INIT = "const log = createHookLogger(metadata);"

def process_file(path: Path):
    content = path.read_text(encoding="utf-8")
    lines = content.splitlines()
    modified = False

    # Ensure metadata-init logger is present
    if LOGGER_INIT not in content:
        for i, line in enumerate(lines):
            if line.strip().startswith("const metadata"):
                # find end of metadata block
                for j in range(i+1, len(lines)):
                    if lines[j].strip() == "};":
                        lines.insert(j+1, LOGGER_INIT)
                        modified = True
                        break
                break

    # Wrap all log(...) calls
    new_lines = []
    for line in lines:
        if re.search(r"log\(\s*\{", line) and "createHookLogger" not in line:
            indent = re.match(r"^(\s*)", line).group(1)
            wrapped = [
                indent + "try {",
                line,
                indent + "} catch(e) {",
                indent + f"    console.error(`[{indent.strip()}] log failed: ${'{e}'});",
                indent + "}"
            ]
            new_lines.extend(wrapped)
            modified = True
        else:
            new_lines.append(line)

    if modified:
        path.write_text("\n".join(new_lines), encoding="utf-8")
        print(f"[✓] Fixed {path.name}")

def main():
    for path in HOOKS_DIR.glob("hook_*.js"):
        if HOOK_PATTERN.match(path.name):
            process_file(path)

if __name__ == "__main__":
    main()
