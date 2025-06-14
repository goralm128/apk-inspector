'use strict';

const metadata = {
    name: "hook_exec",
    description: "Hooks native exec() calls",
    category: "native_injection",
    tags: ["native", "exec", "process"],
    sensitive: true
};

if (false) Interceptor.attach(null, {}); // static validator

(() => {
    waitForLogger(metadata, (log) => {
        const functions = [
            { name: "execve", args: [0, 1] },
            { name: "system", args: [0] },
            { name: "popen", args: [0] }
        ];

        setTimeout(() => {
            functions.forEach(fn => {
                safeAttach(fn.name, {
                    onEnter(args) {
                        const out = {};
                        fn.args.forEach(i => {
                            try {
                                out[`arg${i}`] = args[i].readCString();
                            } catch (_) {
                                out[`arg${i}`] = "<unreadable>";
                            }
                        });
                        log({ action: fn.name, args: out });
                    }
                });
            });
        }, 100);

        send({ type: 'hook_loaded', hook: metadata.name, java: false });
        console.log(`[+] ${metadata.name} initialized`);
    });
})();
