'use strict';

(async function () {
  const metadata = {
    name: "hook_io_net",
    category: "network",
    description: "Hooks native socket I/O and flags suspicious C2 indicators",
    tags: ["native", "network", "send", "recv", "threat_intel", "c2"],
    sensitive: true,
    entrypoint: "native"
  };

  const C2_IPS = new Set([
    "192.99.251.51", "31.170.161.216", "95.211.216.148",
    "27.255.79.225", "121.42.149.52", "103.207.85.8",
    "62.204.41.189", "93.48.80.252", "85.101.222.222"
  ]);

  const C2_PORTS = new Set([23, 80, 443, 502, 5037, 5555, 4444, 8080, 8443, 2323, 3000, 995]);

  const resolveFdSock = (fd) => {
    try {
      const link = `/proc/${Process.id}/fd/${fd}`;
      const target = new File(link, "r").readlink();
      const match = target.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]:(\d+)/);
      if (match) return { ip: match[1], port: parseInt(match[2], 10) };
    } catch (_) {}
    return null;
  };

  const isFlagged = (ip, port) => {
    const flagged_ip = C2_IPS.has(ip);
    const flagged_port = C2_PORTS.has(port);
    const tags = [
      ...(flagged_ip ? ["known_c2_ip"] : []),
      ...(flagged_port ? ["known_c2_port"] : [])
    ];
    return { flagged_ip, flagged_port, tags };
  };

  const formatBacktrace = (ctx) => {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`);
    } catch (_) {
      return ["<no backtrace>"];
    }
  };

  try {
    const log = await waitForLogger(metadata);

    const hookSendRecv = async (fnName) => {
      await safeAttach(fnName, {
        onEnter(args) {
          this.fn = fnName;
          this.fd = args?.[0]?.toInt32?.() ?? -1;
          this.buf = args?.[1];
          this.len = args?.[2]?.toInt32?.() ?? 0;
          this.ctx = this.context;

          const sock = resolveFdSock(this.fd);
          this.ip = sock?.ip || "<unknown>";
          this.port = sock?.port || -1;
        },
        onLeave(retval) {
          const bytes = retval?.toInt32?.() ?? -1;
          const { flagged_ip, flagged_port, tags: threat_tags } = isFlagged(this.ip, this.port);
          const suspicious = flagged_ip || flagged_port || bytes > 8192;

          const args = {
            direction: this.fn === "send" ? "outbound" : "inbound",
            fd: this.fd,
            ip: this.ip,
            port: this.port,
            bytes,
            error: bytes < 0,
            suspicious,
            threat_tags
          };

          if (bytes > 0 && bytes <= 4096) {
            try {
              const data = Memory.readByteArray(this.buf, bytes);
              args.buffer_sha1 = Crypto.digest("sha1", data, { encoding: "hex" });
            } catch (_) {
              args.buffer_sha1 = "<unreadable>";
            }
          }

          const event = buildEvent({
            metadata,
            action: this.fn,
            context: { stack: formatBacktrace(this.ctx) },
            args,
            suspicious,
            tags: metadata.tags.concat(threat_tags)
          });

          log(event);
          console.log(`[hook_io_net] ${this.fn}(${this.fd}) ${bytes} bytes → ${this.ip}:${this.port} [suspicious=${suspicious}]`);
        }
      }, null, {
        maxRetries: 10,
        retryInterval: 250,
        verbose: true
      });

      console.log(`[hook_io_net] Hooked ${fnName}`);
    };

    await hookSendRecv("send");
    await hookSendRecv("recv");

    log(buildEvent({ metadata, action: "hook_loaded" }));
    send({ type: 'hook_loaded', hook: metadata.name });
    console.log(`[+] ${metadata.name} initialized`);
  } catch (e) {
    console.error(`[hook_io_net] Initialization failed: ${e}`);
  }
})();
