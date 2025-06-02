'use strict';

/**
 * Hook Metadata
 */
const metadata = {
    name: "hook_native_sensitive",
    sensitive: true,
    tags: ["native", "exec", "fork", "process"]
};

(function () {
    const functions = [
        { name: "system", args: [0] },
        { name: "execve", args: [0, 1] },
        { name: "dlopen", args: [0] },
        { name: "popen", args: [0] },
        { name: "fork", args: [] },
        { name: "CreateProcessW", args: [0, 1] },
        { name: "CreateProcessA", args: [0, 1] }
    ];

    const logNative = createHookLogger({
        hook: "native_sensitive_fn",
        category: "native_injection",
        tags: metadata.tags,
        description: "Hooks sensitive native functions",
        sensitive: metadata.sensitive
    });

    function safeReadCString(ptr) {
        try { return ptr.readCString(); } catch (_) { return "<unreadable>"; }
    }

    for (const fn of functions) {
        const addr = Module.findExportByName(null, fn.name);
        if (!addr) continue;

        Interceptor.attach(addr, {
            onEnter: function (args) {
                const out = {};
                for (let i = 0; i < fn.args.length; i++) {
                    out[`arg${fn.args[i]}`] = safeReadCString(args[fn.args[i]]);
                }

                logNative({
                    action: fn.name,
                    args: out
                });
            }
        });
    }
})();
