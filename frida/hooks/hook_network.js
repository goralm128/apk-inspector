'use strict';

const metadata = {
    name: "hook_network",
    category: "network",
    description: "Intercepts native socket connect() calls",
    tags: ["network", "native", "socket"],
    sensitive: true
};

function isSuspiciousIP(ip) {
    return /^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[0-1])/.test(ip);
}

function parseSockAddr(addr) {
    const family = addr.readU16();
    if (family === 2) {  // AF_INET
        const port = ntohs(addr.add(2).readU16());
        const ip = [
            addr.add(4).readU8(),
            addr.add(5).readU8(),
            addr.add(6).readU8(),
            addr.add(7).readU8()
        ].join('.');
        return { family, port, ip };
    }
    return { family, port: -1, ip: "<non-IPv4>" };
}

function ntohs(n) {
    return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
}

(async () => {
    try {
        const log = await waitForLogger(metadata);
        const addr = Module.getExportByName(null, "connect");

        Interceptor.attach(addr, {
            onEnter(args) {
                try {
                    const sockAddr = args[1];
                    const { family, port, ip } = parseSockAddr(sockAddr);
                    const suspicious = isSuspiciousIP(ip);

                    log({
                        action: "connect",
                        family,
                        port,
                        ip,
                        suspicious
                    });
                } catch (e) {
                    console.error(`[${metadata.name}] parsing failed: ${e}`);
                }
            }
        });

        send({ type: 'hook_loaded', hook: metadata.name, java: false });
        console.log(`[+] ${metadata.name} initialized`);
    } catch (e) {
        console.error(`[${metadata.name}] Initialization failed: ${e}`);
    }
})();
