'use strict';

const metadata = {
    name: "hook_readwrite",
    category: "filesystem",
    description: "Hooks native read/write file operations",
    tags: ["native", "io", "read", "write"],
    sensitive: true
};

if (false) Interceptor.attach(null, {}); // static validator

(() => {
    waitForLogger(metadata, (log) => {
        const actions = ["read", "write"];

        setTimeout(() => {
            actions.forEach((name) => {
                safeAttach(name, {
                    onEnter(args) {
                        this.fd = args[0]?.toInt32() ?? -1;
                    },
                    onLeave(retval) {
                        const bytes = retval.toInt32();
                        const event = {
                            action: name,
                            direction: name === "write" ? "outbound" : "inbound",
                            fd: this.fd,
                            bytes,
                            error: bytes < 0,
                            threadId: Process.getCurrentThreadId()
                        };
                        if (name === "write") event.bytes_written = bytes;
                        log(event);
                    }
                });
            });
        }, 100);

        send({ type: 'hook_loaded', hook: metadata.name, java: false });
        console.log(`[+] ${metadata.name} initialized`);
    });
})();
