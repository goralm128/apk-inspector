'use strict';

const metadata = {
    name: "hook_native_sensitive",
    category: "native_injection",
    description: "Hooks sensitive native APIs like fork, exec",
    tags: ["native", "exec", "fork", "process"],
    sensitive: true
};

(() => {
    waitForLogger(metadata, (log) => {
        const fns = [
            "system", "execve", "dlopen", "popen", "fork",
            "CreateProcessW", "CreateProcessA"
        ].map(name => ({ name, args: [0, 1] }));

        for (const fn of fns) {
            const addr = Module.findExportByName(null, fn.name);
            if (!addr) continue;

            Interceptor.attach(addr, {
                onEnter(args) {
                    const out = {};
                    for (const i of fn.args) {
                        try {
                            out[`arg${i}`] = args[i].readCString();
                        } catch (_) {
                            out[`arg${i}`] = "<unreadable>";
                        }
                    }
                    log({ hook: metadata.name, action: fn.name, args: out });
                }
            });
        }

        send({ type: 'hook_loaded', hook: metadata.name, java: false });
        console.log(`[+] ${metadata.name} initialized`);
    });
})();
