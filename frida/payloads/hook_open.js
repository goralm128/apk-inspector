'use strict';

function safeAttach(symbol, pathArgIndex) {
    const addr = Module.findExportByName("libc.so", symbol);
    if (!addr) return;

    Interceptor.attach(addr, {
        onEnter(args) {
            try {
                const path = Memory.readUtf8String(args[pathArgIndex]);
                const flags = args[pathArgIndex + 1].toInt32();

                if (path.startsWith("/proc/") || path.startsWith("/dev/ashmem")) return;

                log({
                    event: "open",
                    category: "filesystem",
                    source: `libc.${symbol}`,
                    path,
                    flags,
                    tid: Process.getCurrentThreadId()
                });
            } catch (e) {
                // Fail silently to avoid crashing
            }
        }
    });
}

["open", "open64"].forEach(sym => safeAttach(sym, 0));
["openat", "openat64", "openat2"].forEach(sym => safeAttach(sym, 1));

log({ event: "File open hooks loaded", category: "system", source: "frida" });
