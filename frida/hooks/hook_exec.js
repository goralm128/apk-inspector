'use strict';

const metadata = {
    name: "hook_exec",
    description: "Hooks native exec() calls",
    category: "native_injection",
    tags: ["native", "exec", "process"],
    sensitive: true
};

function tryReadCString(ptr) {
    try {
        return ptr.readCString();
    } catch (_) {
        return "<unreadable>";
    }
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
                        log({
                            action: fn.name,
                            args: out,
                            thread: get_thread_name(),
                            stack: get_java_stack()
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
