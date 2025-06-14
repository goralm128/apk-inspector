'use strict';

const metadata = {
    name: "hook_network",
    category: "network",
    description: "Intercepts native socket APIs",
    tags: ["network", "native", "socket"],
    sensitive: true
};

(() => {
    waitForLogger(metadata, (log) => {
        function ntohs(n) { return ((n & 0xff) << 8) | ((n >> 8) & 0xff); }
        function intToIP(v) { return [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff].join("."); }

        try {
            const addr = Module.getExportByName(null, "connect");
            Interceptor.attach(addr, {
                onEnter(args) {
                    try {
                        const s = args[1];
                        const family = s.readU16();
                        const port = ntohs(s.add(2).readU16());
                        const ip = intToIP(s.add(4).readU32());
                        log({ hook: metadata.name, action: "connect", family, port, ip });
                    } catch (e) {
                        console.error(`[${metadata.name}] parsing failed: ${e}`);
                    }
                }
            });
        } catch (e) {
            console.error(`[${metadata.name}] Hook failed: ${e}`);
        }

        send({ type: 'hook_loaded', hook: metadata.name, java: false });
        console.log(`[+] ${metadata.name} initialized`);
    });
})();
