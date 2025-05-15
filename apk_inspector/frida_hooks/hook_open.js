function safeAttach(symbol, pathArgIndex) {
    var addr = Module.findExportByName("libc.so", symbol);
    if (addr !== null) {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var path = Memory.readUtf8String(args[pathArgIndex]);
                    var flags = args[pathArgIndex + 1].toInt32();

                    // Optional filtering of noise
                    if (path.startsWith("/proc/") || path.startsWith("/dev/ashmem")) return;

                    send({
                        event: "file_opened",
                        path: path,
                        flags: flags,
                        timestamp: new Date().toISOString(),
                        tid: Process.getCurrentThreadId(),
                        classification: classifyPath(path)
                    });
                } catch (e) {
                    // Silently fail to avoid crashes
                }
            }
        });
    }
}

function classifyPath(path) {
    if (!path) return "unknown";
    path = path.toLowerCase();
    if (path.includes("token") || path.includes("secret") || path.includes("key")) return "sensitive";
    if (path.includes("/sdcard/") || path.includes("/data/data/")) return "app_storage";
    return "general";
}

// Native syscalls
safeAttach("open", 0);
safeAttach("open64", 0);
safeAttach("openat", 1);
safeAttach("openat64", 1);
safeAttach("openat2", 1); // Correct for both 32-bit and 64-bit