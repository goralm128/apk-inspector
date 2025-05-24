'use strict';

const MAX_CAPTURE_LEN = 2048;

function getTimestamp() {
    return new Date().toISOString();
}

function ntohs(n) {
    return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
}

function classifyData(data) {
    if (!data || data === '[binary or unreadable]') return 'binary';

    const trimmed = data.trim();

    // --- Priority content-based classification ---

    // Detect HTTP method
    if (/^(GET|POST|PUT|DELETE|CONNECT|OPTIONS|HEAD)\s/i.test(trimmed)) return 'http';

    // Detect JSON
    if ((trimmed.startsWith('{') || trimmed.startsWith('[')) && (trimmed.endsWith('}') || trimmed.endsWith(']'))) {
        try {
            JSON.parse(trimmed);
            return 'json';
        } catch {
            // Invalid JSON, fall through
        }
    }

    // TLS Handshake start (binary pattern)
    if (trimmed.length > 2 && trimmed.charCodeAt(0) === 0x16 && trimmed.charCodeAt(1) === 0x03) {
        return 'tls_handshake';
    }

    // Detect JWT
    if (/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/.test(trimmed)) return 'jwt';

    // Detect API key/token-like patterns
    if (/[\w\-]{20,}/.test(trimmed) && /key|token|auth/i.test(trimmed)) return 'api_key';

    // Mostly printable?
    if (/^[\x20-\x7E\r\n\t]+$/.test(trimmed)) return 'text';

    return 'binary';
}

function parseSockAddr(ptr) {
    try {
        const family = Memory.readU16(ptr);
        if (family === 2) {
            const port = Memory.readU16(ptr.add(2));
            const ip_raw = Memory.readU32(ptr.add(4));
            const ip = [
                ip_raw & 0xff,
                (ip_raw >> 8) & 0xff,
                (ip_raw >> 16) & 0xff,
                (ip_raw >> 24) & 0xff
            ].join(".");
            return { family: "IPv4", ip, port: ntohs(port) };
        } else if (family === 10) {
            const ip_parts = [];
            for (let i = 0; i < 8; i++) {
                ip_parts.push(("0000" + Memory.readU16(ptr.add(8 + i * 2)).toString(16)).slice(-4));
            }
            const ip = ip_parts.join(":");
            const port = Memory.readU16(ptr.add(2));
            return { family: "IPv6", ip, port: ntohs(port) };
        } else if (family === 1) {
            return { family: "AF_UNIX", note: "Unix domain socket - local IPC" };
        } else {
            return { error: `Unsupported family: ${family}`, family: `AF_${family}` };
        }
    } catch (e) {
        return { error: "Failed to parse sockaddr", details: e.message };
    }
}

function getPeerAddr(fd) {
    try {
        const sockaddr = Memory.alloc(128);
        const lenPtr = Memory.alloc(4);
        Memory.writeU32(lenPtr, 128);
        const getpeername = new NativeFunction(
            Module.findExportByName("libc.so", "getpeername"),
            'int',
            ['int', 'pointer', 'pointer']
        );
        if (getpeername(fd, sockaddr, lenPtr) === 0) {
            return parseSockAddr(sockaddr);
        }
    } catch (e) {
        return { error: "getpeername failed", details: e.message };
    }
    return { error: "getpeername failed" };
}

function readData(ptr, len) {
    if (len <= 0 || len > MAX_CAPTURE_LEN) return "[binary or unreadable]";
    try {
        return Memory.readUtf8String(ptr, len);
    } catch {
        return "[binary or unreadable]";
    }
}

function log(event) {
    event.timestamp = getTimestamp();
    event.classification = classifyData(event.data);

    // Optional: add quick tags for GUI filters
    event.tags = [];

    if (event.classification === 'jwt') event.tags.push('token', 'auth');
    if (event.classification === 'api_key') event.tags.push('sensitive');
    if (event.classification === 'http') event.tags.push('web', 'plaintext');

    send(event);
}

// --- Standard Socket Hooks ---

Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
    onEnter: function (args) {
        this.addr = parseSockAddr(args[1]);
    },
    onLeave: function (retval) {
        log({ event: "connect", address: this.addr, result: retval.toInt32() });
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "send"), {
    onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave: function () {
        const addr = getPeerAddr(this.fd);
        const data = readData(this.buf, this.len);
        log({ event: "send", fd: this.fd, address: addr, length: this.len, data });
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "sendto"), {
    onEnter: function (args) {
        const fd = args[0].toInt32();
        const buf = args[1];
        const len = args[2].toInt32();
        const sockaddr = args[4];
        const addr = sockaddr.isNull() ? getPeerAddr(fd) : parseSockAddr(sockaddr);
        const data = readData(buf, len);
        log({ event: "sendto", fd, address: addr, length: len, data });
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "recv"), {
    onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
    },
    onLeave: function (retval) {
        const len = retval.toInt32();
        const addr = getPeerAddr(this.fd);
        const data = readData(this.buf, len);
        log({ event: "recv", fd: this.fd, address: addr, length: len, data });
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "recvfrom"), {
    onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.sockaddr = args[4];
    },
    onLeave: function (retval) {
        const len = retval.toInt32();
        const addr = this.sockaddr.isNull() ? getPeerAddr(this.fd) : parseSockAddr(this.sockaddr);
        const data = readData(this.buf, len);
        log({ event: "recvfrom", fd: this.fd, address: addr, length: len, data });
    }
});

// --- TLS/SSL Hooks ---

function hookSSL() {
    const SSL_write = Module.findExportByName(null, "SSL_write");
    const SSL_read = Module.findExportByName(null, "SSL_read");
    const SSL_get_fd = Module.findExportByName(null, "SSL_get_fd");

    if (SSL_write) {
        Interceptor.attach(SSL_write, {
            onEnter: function (args) {
                this.ssl = args[0];
                this.buf = args[1];
                this.len = args[2].toInt32();
            },
            onLeave: function () {
                const fd = new NativeFunction(SSL_get_fd, 'int', ['pointer'])(this.ssl);
                const addr = getPeerAddr(fd);
                const data = readData(this.buf, this.len);
                log({ event: "SSL_write", fd, address: addr, length: this.len, data });
            }
        });
    }

    if (SSL_read) {
        Interceptor.attach(SSL_read, {
            onEnter: function (args) {
                this.ssl = args[0];
                this.buf = args[1];
            },
            onLeave: function (retval) {
                const len = retval.toInt32();
                if (len <= 0) return;
                const fd = new NativeFunction(SSL_get_fd, 'int', ['pointer'])(this.ssl);
                const addr = getPeerAddr(fd);
                const data = readData(this.buf, len);
                log({ event: "SSL_read", fd, address: addr, length: len, data });
            }
        });
    }
}

hookSSL();
log({ event: "Network + TLS hooks loaded", data: "" });
