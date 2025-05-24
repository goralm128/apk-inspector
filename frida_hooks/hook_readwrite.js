'use strict';

const MAX_CAPTURE_LEN = 4096;
const fdMap = {};

function getTimestamp() {
    return new Date().toISOString();
}

function readData(ptr, len) {
    if (len <= 0 || len > MAX_CAPTURE_LEN) return "[binary or unreadable]";
    try {
        return Memory.readUtf8String(ptr, len);
    } catch {
        return "[binary or unreadable]";
    }
}

function classifyPath(path) {
    if (!path) return "unknown";
    const p = path.toLowerCase();
    if (p.includes("token") || p.includes("secret") || p.includes("key")) return "sensitive";
    if (p.includes("config") || p.includes("settings")) return "config";
    if (p.includes("/sdcard/") || p.includes("/data/data/")) return "app_storage";
    if (p.includes("/system/") || p.includes("/vendor/")) return "system";
    return "general";
}

function log(event) {
    if (event.fd && fdMap[event.fd]) {
        event.path = fdMap[event.fd];
        event.classification = classifyPath(fdMap[event.fd]);
    }
    event.timestamp = getTimestamp();
    send(event);
}

function safeAttach(symbol, handler) {
    const addr = Module.findExportByName("libc.so", symbol);
    if (addr) {
        Interceptor.attach(addr, handler);
    }
}

// --- Track open() and openat() to map fd -> path ---

function trackFdOp(symbol, pathArgIndex) {
    const addr = Module.findExportByName("libc.so", symbol);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter(args) {
                this.path = Memory.readUtf8String(args[pathArgIndex]);
            },
            onLeave(retval) {
                const fd = retval.toInt32();
                if (fd > 0) {
                    fdMap[fd] = this.path;
                }
            }
        });
    }
}

["open", "open64"].forEach(sym => trackFdOp(sym, 0));
["openat", "openat64", "openat2"].forEach(sym => trackFdOp(sym, 1));

// --- POSIX read/write ---

safeAttach("read", {
    onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
    },
    onLeave(retval) {
        const len = retval.toInt32();
        const data = readData(this.buf, len);
        log({ event: "read", fd: this.fd, length: len, data });
    }
});

safeAttach("write", {
    onEnter(args) {
        const fd = args[0].toInt32();
        const buf = args[1];
        const len = args[2].toInt32();
        const data = readData(buf, len);
        log({ event: "write", fd, length: len, data });
    }
});

// --- readv / writev ---

safeAttach("readv", {
    onEnter(args) {
        this.fd = args[0].toInt32();
        this.iov = args[1];
        this.iovcnt = args[2].toInt32();
    },
    onLeave(retval) {
        let totalLen = 0;
        let allData = [];
        for (let i = 0; i < this.iovcnt; i++) {
            const base = Memory.readPointer(this.iov.add(i * Process.pointerSize * 2));
            const len = Memory.readU32(this.iov.add(i * Process.pointerSize * 2 + Process.pointerSize));
            totalLen += len;
            allData.push(readData(base, len));
        }
        log({ event: "readv", fd: this.fd, length: totalLen, data: allData.join("") });
    }
});

safeAttach("writev", {
    onEnter(args) {
        this.fd = args[0].toInt32();
        const iov = args[1];
        const iovcnt = args[2].toInt32();
        let totalLen = 0;
        let allData = [];
        for (let i = 0; i < iovcnt; i++) {
            const base = Memory.readPointer(iov.add(i * Process.pointerSize * 2));
            const len = Memory.readU32(iov.add(i * Process.pointerSize * 2 + Process.pointerSize));
            totalLen += len;
            allData.push(readData(base, len));
        }
        log({ event: "writev", fd: this.fd, length: totalLen, data: allData.join("") });
    }
});

// --- FILE* stdio ---

safeAttach("fread", {
    onEnter(args) {
        this.ptr = args[0];
        this.size = args[1].toInt32();
        this.nmemb = args[2].toInt32();
    },
    onLeave(retval) {
        const count = retval.toInt32();
        const len = count * this.size;
        const data = readData(this.ptr, len);
        log({ event: "fread", length: len, data });
    }
});

safeAttach("fwrite", {
    onEnter(args) {
        const ptr = args[0];
        const size = args[1].toInt32();
        const nmemb = args[2].toInt32();
        const len = size * nmemb;
        const data = readData(ptr, len);
        log({ event: "fwrite", length: len, data });
    }
});

// --- Optional 64-bit variants ---
["read64", "write64", "fread64", "fwrite64"].forEach(name => {
    safeAttach(name, {
        onEnter(args) {
            this.args = args;
            this.fn = name;
        },
        onLeave(retval) {
            const len = retval.toInt32();
            const ptr = this.args[1];
            const data = readData(ptr, len);
            log({ event: this.fn, length: len, data });
        }
    });
});

log({ event: "File I/O hooks loaded", data: "" });
