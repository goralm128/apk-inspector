'use strict';

/**
 * Hook Metadata
 */
const metadata = {
    name: "hook_exec",
    sensitive: true,
    tags: ["native", "exec", "process"]
};

(function () {
    const sensitiveFns = [
        { name: "execve", args: [0, 1] },
        { name: "system", args: [0] },
        { name: "popen", args: [0] }
    ];

    const logExec = createHookLogger({
        hook: "exec_native",
        category: "native_injection",
        tags: metadata.tags,
        description: "Hooks native execution functions",
        sensitive: metadata.sensitive
    });

    function safeReadCString(ptr) {
        try { return ptr.readCString(); } catch (_) { return "<unreadable>"; }
    }

    for (const fn of sensitiveFns) {
        const addr = Module.findExportByName(null, fn.name);
        if (!addr) continue;

        Interceptor.attach(addr, {
            onEnter: function (args) {
                const argsOut = {};
                for (let i = 0; i < fn.args.length; i++) {
                    argsOut[`arg${fn.args[i]}`] = safeReadCString(args[fn.args[i]]);
                }

                logExec({
                    action: fn.name,
                    args: argsOut
                });
            }
        });
    }
})();
