'use strict';

const metadata = {
    name: "hook_open",
    category: "filesystem",
    description: "Hooks native file open operations",
    tags: ["native", "file", "fs", "fopen", "openat"],
    sensitive: true
};

if (false) Interceptor.attach(null, {}); // static validator

(() => {
    waitForLogger(metadata, (log) => {
        function hookFile(func, argIndex) {
            const callbacks = {
                onEnter(args) {
                    try {
                        this.path = Memory.readUtf8String(args[argIndex]);
                    } catch (_) {
                        this.path = "<unreadable>";
                    }
                    this.func = func;
                },
                onLeave(ret) {
                    try {
                        log({
                            action: this.func,
                            file_path: this.path,
                            retval: ret.toInt32(),
                            threadId: Process.getCurrentThreadId()
                        });
                    } catch (e) {
                        console.error(`[${metadata.name}] Logging failed for ${func}: ${e}`);
                    }
                }
            };

            setTimeout(() => {
                const hooked = safeAttach(func, callbacks);
                if (!hooked) console.warn(`[${metadata.name}] Skipped hook for ${func}`);
            }, 100);
        }

        hookFile("open", 0);
        hookFile("openat", 1);
        hookFile("fopen", 0);

        send({ type: 'hook_loaded', hook: metadata.name, java: false });
        console.log(`[+] ${metadata.name} initialized`);
    });
})();
