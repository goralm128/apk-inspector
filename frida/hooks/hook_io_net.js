'use strict';

(async function () {
  const metadata = {
    name: "hook_io_net",
    category: "network",
    description: "Hooks native socket I/O and flags C2 indicators (ports, IPs)",
    tags: ["native", "network", "send", "recv", "threat_intel"],
    sensitive: true,
    entrypoint: "native"
  };

  const C2_IPS = new Set([
    "192.99.251.51", "31.170.161.216", "95.211.216.148",
    "27.255.79.225", "121.42.149.52", "103.207.85.8",
    "62.204.41.189", "93.48.80.252", "85.101.222.222"
  ]);

  const C2_PORTS = new Set([
    23, 80, 443, 502, 5037, 5555, 4444, 8080, 8443, 2323, 3000, 995
  ]);

  function resolveFdSock(fd) {
    try {
      const link = `/proc/${Process.id}/fd/${fd}`;
      const target = new File(link, "r").readlink();
      const m = target.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]:(\d+)/);
      if (m) return { ip: m[1], port: parseInt(m[2], 10) };
    } catch (_) {}
    return null;
  }

  function isFlagged(ip, port) {
    return {
      flagged_ip: C2_IPS.has(ip),
      flagged_port: C2_PORTS.has(port),
      tags: [
        ...(C2_IPS.has(ip) ? ["known_c2_ip"] : []),
        ...(C2_PORTS.has(port) ? ["known_c2_port"] : [])
      ]
    };
  }

  function formatBacktrace(ctx) {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"} @ ${sym.address}`);
    } catch (_) {
      return ["<no backtrace>"];
    }
  }

  try {
    const log = await waitForLogger(metadata);
    const funcs = ["send", "recv"];

    for (const fn of funcs) {
      try {
        await safeAttach(fn, {
          onEnter(args) {
            this.fn = fn;
            this.fd = args[0]?.toInt32?.() ?? -1;
            this.buf = args[1];
            this.len = args[2]?.toInt32?.() ?? 0;
            this.context = this.context;

            const sock = resolveFdSock(this.fd);
            this.ip = sock?.ip || "<unknown>";
            this.port = sock?.port || -1;
          },
          onLeave(retval) {
            const bytes = retval?.toInt32?.() ?? -1;
            const { flagged_ip, flagged_port, tags } = isFlagged(this.ip, this.port);

            const event = {
              action: this.fn,
              direction: this.fn === "send" ? "outbound" : "inbound",
              fd: this.fd,
              ip: this.ip,
              port: this.port,
              bytes,
              error: bytes < 0,
              suspicious: flagged_ip || flagged_port || bytes > 8192,
              threat_tags: tags,
              thread: get_thread_name(),
              threadId: Process.getCurrentThreadId(),
              processId: Process.id,
              stack: formatBacktrace(this.context)
            };

            if (bytes > 0 && bytes <= 4096) {
              try {
                const data = Memory.readByteArray(this.buf, bytes);
                event.buffer_sha1 = Crypto.digest("sha1", data, { encoding: "hex" });
              } catch (_) {
                event.buffer_sha1 = "<unreadable>";
              }
            }

            console.log(`[hook_io_net] ${this.fn}(${this.fd}) ${bytes} bytes → ${this.ip}:${this.port}`);
            log(event);
          }
        }, null, {
          maxRetries: 10,
          retryInterval: 250,
          verbose: true
        });

        console.log(`[hook_io_net] Hooked ${fn}`);
      } catch (err) {
        console.error(`[hook_io_net] Failed to hook ${fn}: ${err}`);
      }
    }

    send({ type: 'hook_loaded', hook: metadata.name, java: false });
    console.log(`[+] ${metadata.name} initialized`);

  } catch (e) {
    console.error(`[hook_io_net] Logger setup or hook attach failed: ${e}`);
  }
})();
