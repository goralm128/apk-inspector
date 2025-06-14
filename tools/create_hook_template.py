from pathlib import Path
import sys

def create_hook_template(name: str, category: str, tags: list[str]):
    filename = f"hook_{name}.js"
    path = Path("frida/hooks") / filename

    if path.exists():
        print(f"[!] Hook already exists: {path}")
        return

    tag_str = ", ".join([f'"{t}"' for t in tags])
    template = f"""\
'use strict';

const metadata = {{
    name: "hook_{name}",
    description: "TODO: Describe what this hook does",
    category: "{category}",
    tags: [{tag_str}],
    sensitive: false
}};

(() => {{
    waitForLogger(metadata, (log) => {{
        try {{
            const addr = Module.getExportByName(null, "{name}");
            Interceptor.attach(addr, {{
                onEnter(args) {{
                    log({{ hook: metadata.name, action: "{name}_called" }});
                }}
            }});
        }} catch (e) {{
            console.error(`[{{metadata.name}}] Hook failed: ${{e}}`);
        }}

        send({{ type: 'hook_loaded', hook: metadata.name, java: false }});
        console.log(`[+] {{metadata.name}} initialized`);
    }});
}})();
"""

    path.write_text(template)
    print(f"[✓] Created hook template: {path.resolve()}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python create_hook_template.py <name> <category> [<tag1> <tag2> ...]")
    else:
        create_hook_template(sys.argv[1], sys.argv[2], sys.argv[3:])
