'use strict';

const metadata = {
    name: "hook_socket_io",
    category: "network",
    description: "Hooks native send/recv socket operations",
    tags: ["native", "socket", "send", "recv"],
    sensitive: false
};

(() => {
    waitForLogger(metadata, (log) => {
        function attachSockHook(funcName, direction) {
            let addr = null;
            try {
                addr = Module.getExportByName(null, funcName);
            } catch (err) {
                console.warn(`[${metadata.name}] ${funcName} not found in module exports.`);
                return;
            }

            if (!addr || typeof addr !== 'object' || !addr.isNull && addr.isNull()) {
                console.warn(`[${metadata.name}] Skipping ${funcName}: export not found or invalid.`);
                return;
            }

            try {
                Interceptor.attach(addr, {
                    onEnter(args) {
                        this.fd = args[0].toInt32();
                        this.func = funcName;
                        this.direction = direction;
                    },
                    onLeave(retval) {
                        try {
                            const bytes = retval.toInt32();
                            log({
                                action: this.func,
                                direction: this.direction,
                                fd: this.fd,
                                bytes,
                                error: bytes < 0,
                                threadId: Process.getCurrentThreadId()
                            });
                        } catch (e) {
                            console.error(`[${metadata.name}] Failed to log ${funcName}: ${e}`);
                        }
                    }
                });

                console.log(`[${metadata.name}] Hooked ${funcName}`);
            } catch (e) {
                console.error(`[${metadata.name}] Interceptor.attach failed for ${funcName}: ${e}`);
            }
        }

        ["send", "recv", "sendto", "recvfrom"].forEach(fn =>
            attachSockHook(fn, fn.includes("send") ? "outbound" : "inbound")
        );

        send({ type: 'hook_loaded', hook: metadata.name, java: false });
        console.log(`[+] ${metadata.name} initialized`);
    });
})();
