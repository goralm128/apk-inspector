'use strict';

const MAX_CAPTURE_LEN = 4096;
const fdMap = {};

function readData(ptr, len) {
    if (len <= 0 || len > MAX_CAPTURE_LEN) return "[binary or unreadable]";
    try {
        return Memory.readUtf8String(ptr, len);
    } catch {
        return "[binary or unreadable]";
    }
}

function trackFd(symbol, pathArgIndex) {
    const addr = Module.findExportByName("libc.so", symbol);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter(args) {
            this.path = Memory.readUtf8String(args[pathArgIndex]);
        },
        onLeave(retval) {
            const fd = retval.toInt32();
            if (fd > 0) fdMap[fd] = this.path;
        }
    });
}

["open", "open64"].forEach(sym => trackFd(sym, 0));
["openat", "openat64", "openat2"].forEach(sym => trackFd(sym, 1));

function attachIO(symbol, label) {
    const addr = Module.findExportByName("libc.so", symbol);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
        },
        onLeave(retval) {
            const len = retval.toInt32();
            const data = readData(this.buf, len);
            log({
                event: label,
                category: "filesystem",
                source: `libc.${symbol}`,
                fd: this.fd,
                path: fdMap[this.fd] || undefined,
                length: len,
                data
            });
        }
    });
}

attachIO("read", "read");
attachIO("write", "write");
attachIO("fread", "fread");
attachIO("fwrite", "fwrite");

log({ event: "Read/write hooks loaded", category: "system", source: "frida" });
