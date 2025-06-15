'use strict';

const metadata = {
    name: "hook_io_fs",
    category: "filesystem",
    description: "Hooks native read/write file operations",
    tags: ["native", "read", "write", "fs"],
    sensitive: true
};

if (false) Interceptor.attach(null, {}); // static validator

(async () => {
    try {
        const log = await waitForLogger(metadata);
        const actions = ["read", "write"];

        for (const name of actions) {
            await safeAttach(name, {
                onEnter(args) {
                    this.name = name;
                    this.fd = args[0]?.toInt32?.() ?? -1;
                    this.buf = args[1];
                    this.len = args[2]?.toInt32?.() ?? 0;
                    this.context = this.context;
                    this.path = resolveFdPath(this.fd);
                },
                onLeave(retval) {
                    const bytes = retval?.toInt32?.() ?? -1;
                    const event = {
                        action: this.name,
                        direction: name === "write" ? "outbound" : "inbound",
                        fd: this.fd,
                        file_path: this.path,
                        bytes,
                        error: bytes < 0,
                        suspicious: this.len > 4096 || /proc|cache|su|sh/.test(this.path),
                        threadId: Process.getCurrentThreadId(),
                        processId: Process.id,
                        stack: getBacktrace(this.context)
                    };

                    if (bytes > 0 && bytes < 2048) {
                        try {
                            const buf = Memory.readByteArray(this.buf, bytes);
                            event.buffer_hash = SHA1(buf);
                        } catch (_) {
                            event.buffer_hash = "<failed>";
                        }
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

function resolveFdPath(fd) {
    try {
        const path = `/proc/${Process.id}/fd/${fd}`;
        return new File(path, "r").readlink();
    } catch (_) {
        return "<unknown>";
    }
}

function SHA1(buf) {
    const digest = require('crypto').createHash('sha1');
    digest.update(buf);
    return digest.digest('hex');
}

function getBacktrace(context) {
    try {
        return Thread.backtrace(context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .map(sym => `${sym.name}@${sym.address}`)
            .join("\n");
    } catch (_) {
        return "N/A";
    }
}
