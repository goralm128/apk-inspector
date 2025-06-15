'use strict';

const metadata = {
    name: "hook_io_net",
    category: "network",
    description: "Hooks native socket I/O and flags C2 indicators (ports, IPs)",
    tags: ["native", "network", "send", "recv", "threat_intel"],
    sensitive: true
};

// Known C2 IPs
const C2_IPS = new Set([
    "192.99.251.51", "31.170.161.216", "95.211.216.148",
    "27.255.79.225", "121.42.149.52", "103.207.85.8",
    "62.204.41.189", "93.48.80.252", "85.101.222.222"
]);

// Suspicious ports
const C2_PORTS = new Set([
    23, 80, 443, 502, 5037, 5555, 4444, 8080, 8443, 2323, 3000, 995
]);

(async () => {
    try {
        const log = await waitForLogger(metadata);
        const actions = ["send", "recv"];

        for (const name of actions) {
            await safeAttach(name, {
                onEnter(args) {
                    this.name = name;
                    this.fd = args[0]?.toInt32?.() ?? -1;
                    this.buf = args[1];
                    this.len = args[2]?.toInt32?.() ?? 0;
                    this.context = this.context;

                    const sock = getSocketAddress(this.fd);
                    this.remote_ip = sock?.ip ?? "<unknown>";
                    this.remote_port = sock?.port ?? -1;
                },
                onLeave(retval) {
                    const bytes = retval?.toInt32?.() ?? -1;
                    const flagged_ip = C2_IPS.has(this.remote_ip);
                    const flagged_port = C2_PORTS.has(this.remote_port);

                    const event = {
                        action: this.name,
                        direction: this.name === "send" ? "outbound" : "inbound",
                        fd: this.fd,
                        bytes,
                        ip: this.remote_ip,
                        port: this.remote_port,
                        error: bytes < 0,
                        suspicious: flagged_ip || flagged_port || bytes > 8192,
                        threat_tags: [
                            flagged_ip ? "known_c2_ip" : null,
                            flagged_port ? "known_c2_port" : null
                        ].filter(Boolean),
                        threadId: Process.getCurrentThreadId(),
                        processId: Process.id,
                        stack: getBacktrace(this.context)
                    };

                    if (bytes > 0 && bytes < 4096) {
                        try {
                            const buf = Memory.readByteArray(this.buf, bytes);
                            event.buffer_sha1 = SHA1(buf);
                        } catch (_) {
                            event.buffer_sha1 = "<unreadable>";
                        }
                    }

                    log(event);
                }
            });
        }

        send({ type: 'hook_loaded', hook: metadata.name, java: false });
        console.log(`[+] ${metadata.name} initialized`);
    } catch (e) {
        console.error(`[${metadata.name}] Initialization failed: ${e}`);
    }
})();

function SHA1(buf) {
    const digest = require('crypto').createHash('sha1');
    digest.update(buf);
    return digest.digest('hex');
}

function getBacktrace(context) {
    try {
        return Thread.backtrace(context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .map(sym => `${sym.name}@${sym.address}`)
            .join("\n");
    } catch (_) {
        return "N/A";
    }
}

function getSocketAddress(fd) {
    try {
        const path = `/proc/${Process.id}/fd/${fd}`;
        const link = new File(path, "r").readlink();
        const match = link.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]:(\d+)/);
        if (match) {
            return { ip: match[1], port: parseInt(match[2]) };
        }
    } catch (_) {}
    return null;
}
