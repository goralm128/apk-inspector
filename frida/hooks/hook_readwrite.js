'use strict';

/**
 * Hook Metadata (required for discovery)
 */
const metadata = {
    name: "hook_readwrite",
    sensitive: true,
    description: "Hooks native read() and write() to observe I/O",
    tags: ["native", "io", "read", "write"]
};

// Reusable hook loggers for read() and write()
const logRead = createHookLogger({
    hook: "read",
    category: "filesystem",
    tags: metadata.tags,
    description: "Hooks native read() syscall",
    sensitive: metadata.sensitive
});

const logWrite = createHookLogger({
    hook: "write",
    category: "filesystem",
    tags: metadata.tags,
    description: "Hooks native write() syscall",
    sensitive: metadata.sensitive
});

// Generic attach helper
function tryHook(funcName, handler) {
    try {
        const ptr = Module.getExportByName(null, funcName);
        Interceptor.attach(ptr, handler);
        console.log(`[*] Hooked ${funcName}`);
    } catch (e) {
        console.error(`Failed to hook ${funcName}:`, e);
    }
}

// Attach native read()
tryHook("read", {
    onEnter(args) {
        this.fd = args[0].toInt32();
    },
    onLeave(retval) {
        logRead({
            action: "read",
            fd: this.fd,
            bytes: retval.toInt32()
        });
    }
});

// Attach native write()
tryHook("write", {
    onEnter(args) {
        this.fd = args[0].toInt32();
        this.len = args[2].toInt32();
    },
    onLeave(retval) {
        logWrite({
            action: "write",
            fd: this.fd,
            bytes_written: retval.toInt32()
        });
    }
});
