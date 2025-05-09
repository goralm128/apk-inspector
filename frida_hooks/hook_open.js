function safeAttach(symbol, argIndex) {
    var addr = Module.findExportByName("libc.so", symbol);
    if (addr !== null) {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var path = Memory.readUtf8String(args[argIndex]);
                    send({ event: "file_opened", path: path });
                } catch (e) {
                    // Just in case: some args might be invalid or crashy
                }
            }
        });
    }
}

// Common native open-style functions on Android
safeAttach("open", 0);
safeAttach("openat", 1);
safeAttach("open64", 0);
safeAttach("openat64", 1);