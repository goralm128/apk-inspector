'use strict';

const metadata = {
    name: "hook_readwrite",
    category: "filesystem",
    description: "Hooks native read/write file operations with enhanced context",
    tags: ["native", "io", "read", "write"],
    sensitive: true
};

if (false) Interceptor.attach(null, {}); // static validator

(async () => {
    try {
        const log = await waitForLogger(metadata);
        const actions = ["read", "write"];

        function resolveFdPath(fd) {
            try {
                const path = `/proc/${Process.id}/fd/${fd}`;
                return new File(path, "r").readlink();
            } catch (_) {
                return "<unknown>";
            }
        }

        for (const name of actions) {
            await safeAttach(name, {
                onEnter(args) {
                    this.fd = args[0]?.toInt32() ?? -1;
                    this.buf = args[1];
                    this.len = args[2]?.toInt32() ?? 0;
                    this.path = resolveFdPath(this.fd);
                    this.func = name;
                },
                onLeave(retval) {
                    const bytes = retval?.toInt32?.() ?? -1;
                    const suspicious = this.len > 4096 || /data|proc|cache/i.test(this.path);

                    const event = {
                        action: this.func,
                        direction: this.func === "write" ? "outbound" : "inbound",
                        fd: this.fd,
                        file_path: this.path,
                        bytes,
                        suspicious,
                        threadId: Process.getCurrentThreadId(),
                        processId: Process.id,
                        error: bytes < 0
                    };

                    try {
                        // Add optional hash preview for writes
                        if (this.func === "write" && this.buf && bytes > 0 && bytes < 2048) {
                            const buf = Memory.readByteArray(this.buf, bytes);
                            const hash = buf ? SHA1(buf) : null;
                            if (hash) event.buffer_hash = hash;
                        }

                        // Add native stack
                        event.stack = Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress)
                            .map(sym => `${sym.name}@${sym.address}`)
                            .join("\n");
                    } catch (_) {
                        event.stack = "N/A";
                    }

                    log(event);
                }
            });
        }

        send({ type: 'hook_loaded', hook: metadata.name, java: false });
        console.log(`[+] ${metadata.name} initialized`);
    } catch (e) {
        console.error(`[${metadata.name}] Initialization failed: ${e}`);
    }
})();

// Optional SHA1 helper
function SHA1(buf) {
    const digest = require('crypto').createHash('sha1');
    digest.update(buf);
    return digest.digest('hex');
}
