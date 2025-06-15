'use strict';

const metadata = {
    name: "hook_open",
    category: "filesystem",
    description: "Hooks native file open operations",
    tags: ["native", "file", "fs", "fopen", "openat"],
    sensitive: true
};

if (false) Interceptor.attach(null, {}); // static validator

(async () => {
    try {
        const log = await waitForLogger(metadata);

        async function hookFile(func, argIndex) {
            await safeAttach(func, {
                onEnter(args) {
                    try {
                        this.path = args[argIndex].readUtf8String();
                    } catch (_) {
                        this.path = "<unreadable>";
                    }
                    this.func = func;

                    // Classify sensitive access patterns
                    this.suspicious = [
                        "/proc", "/data/data", "/system/bin/su", "/dev", "/sys", "frida"
                    ].some(keyword => this.path.includes(keyword));
                },
                onLeave(ret) {
                    try {
                        const event = {
                            action: this.func,
                            file_path: this.path,
                            retval: ret.toInt32(),
                            threadId: Process.getCurrentThreadId(),
                            processId: Process.id,
                            suspicious: this.suspicious || false
                        };

                        // Include Java-like stack if available
                        try {
                            event.stack = Thread.backtrace(this.context, Backtracer.ACCURATE)
                                .map(DebugSymbol.fromAddress)
                                .map(sym => `${sym.name} @ ${sym.address}`)
                                .join("\n");
                        } catch (e) {
                            event.stack = "N/A";
                        }

                        log(event);
                    } catch (e) {
                        console.error(`[${metadata.name}] Logging failed for ${this.func}: ${e}`);
                    }
                }
            });
        }

        await hookFile("open", 0);
        await hookFile("openat", 1);
        await hookFile("fopen", 0);

        send({ type: 'hook_loaded', hook: metadata.name, java: false });
        console.log(`[+] ${metadata.name} initialized`);
    } catch (e) {
        console.error(`[${metadata.name}] Initialization failed: ${e}`);
    }
})();
