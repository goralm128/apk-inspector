'use strict';

const metadata = {
    name: "hook_exec",
    description: "Hooks native exec() calls",
    category: "native_injection",
    tags: ["native", "exec", "process"],
    sensitive: true
};

// Suspicious command keywords
const suspiciousKeywords = [
    "sh", "su", "chmod", "mount", "chroot",
    "curl", "wget", "nc", "netcat",
    "am start", "pm install", "frida", "busybox"
];

function tryReadCString(ptr) {
    try {
        return ptr.readCString();
    } catch (_) {
        return "<unreadable>";
    }
}

function classifyExec(args) {
    const str = Object.values(args).join(" ").toLowerCase();
    const matches = suspiciousKeywords.filter(keyword => str.includes(keyword));
    if (matches.length > 0) {
        return {
            label: "suspicious",
            justification: {
                reason: "exec arguments contain known suspicious keywords",
                matches: matches
            }
        };
    }
    return { label: "benign", justification: {} };
}

(async () => {
    try {
        const log = await waitForLogger(metadata);

        const functions = [
            { name: "execve", args: [0, 1], module: "libc.so" },
            { name: "system", args: [0], module: "libc.so" },
            { name: "popen", args: [0], module: "libc.so" }
        ];

        for (const fn of functions) {
            try {
                await safeAttach(fn.name, {
                    onEnter(args) {
                        const out = {};
                        for (const i of fn.args) {
                            out[`arg${i}`] = tryReadCString(args[i]);
                        }

                        const classification = classifyExec(out);
                        log({
                            action: fn.name,
                            args: out,
                            thread: get_thread_name(),
                            stack: get_java_stack(),
                            ...classification
                        });
                    }
                }, fn.module);

                console.log(`[hook_exec] Attached to ${fn.name}`);
            } catch (hookError) {
                console.error(`[hook_exec] Failed to hook ${fn.name}: ${hookError}`);
            }
        }

        send({ type: 'hook_loaded', hook: metadata.name, java: false });
        console.log(`[+] ${metadata.name} initialized`);

    } catch (e) {
        console.error(`[${metadata.name}] Initialization failed: ${e}`);
    }
})();
