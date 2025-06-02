'use strict';

/**
 * Hook Metadata
 */
const metadata = {
    name: "hook_network",
    sensitive: true,
    tags: ["network", "native", "socket"]
};

const logConnect = createHookLogger({
    hook: "connect",
    category: "network",
    tags: metadata.tags,
    description: "Hooks native connect()",
    sensitive: metadata.sensitive
});

function ntohs(n) {
    return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
}

function intToIP(intVal) {
    return [intVal & 0xff, (intVal >> 8) & 0xff, (intVal >> 16) & 0xff, (intVal >> 24) & 0xff].join(".");
}

try {
    const connectPtr = Module.getExportByName(null, "connect");
    Interceptor.attach(connectPtr, {
        onEnter(args) {
            try {
                const sockaddr = args[1];
                const family = sockaddr.readU16();
                const port = ntohs(sockaddr.add(2).readU16());
                const ipRaw = sockaddr.add(4).readU32();
                const ip = intToIP(ipRaw);

                logConnect({
                    action: "connect",
                    family,
                    port,
                    ip
                });
            } catch (err) {
                console.error("connect parsing failed", err);
            }
        }
    });
} catch (e) {
    console.error("Failed to hook 'connect':", e);
}
