'use strict';

const MAX_CAPTURE_LEN = 2048;

function readData(ptr, len) {
    if (len <= 0 || len > MAX_CAPTURE_LEN) return "[binary or unreadable]";
    try {
        return Memory.readUtf8String(ptr, len);
    } catch {
        return "[binary or unreadable]";
    }
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
            return { family: "IPv4", ip, port: ((port & 0xff) << 8) | ((port >> 8) & 0xff) };
        }
    } catch (e) {
        return { error: "Failed to parse sockaddr", details: e.message };
    }
    return {};
}

function getPeerAddr(fd) {
    try {
        const sockaddr = Memory.alloc(128);
        const lenPtr = Memory.alloc(4);
        Memory.writeU32(lenPtr, 128);
        const getpeername = new NativeFunction(Module.findExportByName("libc.so", "getpeername"), 'int', ['int', 'pointer', 'pointer']);
        if (getpeername(fd, sockaddr, lenPtr) === 0) {
            return parseSockAddr(sockaddr);
        }
    } catch (e) {}
    return {};
}

function hookNativeSendRecv() {
    const libc = Module.findExportByName("libc.so", "send");
    if (libc) {
        Interceptor.attach(libc, {
            onEnter(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.len = args[2].toInt32();
            },
            onLeave() {
                const addr = getPeerAddr(this.fd);
                const data = readData(this.buf, this.len);
                log({
                    event: "send",
                    category: "network",
                    source: "libc.send",
                    fd: this.fd,
                    address: addr,
                    length: this.len,
                    data
                });
            }
        });
    }

    ["recv", "recvfrom"].forEach(fn => {
        const fnPtr = Module.findExportByName("libc.so", fn);
        if (fnPtr) {
            Interceptor.attach(fnPtr, {
                onEnter(args) {
                    this.fd = args[0].toInt32();
                    this.buf = args[1];
                    this.sockaddr = args[4];
                },
                onLeave(retval) {
                    const len = retval.toInt32();
                    const addr = this.sockaddr && !this.sockaddr.isNull()
                        ? parseSockAddr(this.sockaddr)
                        : getPeerAddr(this.fd);
                    const data = readData(this.buf, len);
                    log({
                        event: fn,
                        category: "network",
                        source: `libc.${fn}`,
                        fd: this.fd,
                        address: addr,
                        length: len,
                        data
                    });
                }
            });
        }
    });
}

hookNativeSendRecv();
log({ event: "Native network hooks loaded", category: "system", source: "frida" });
