'use strict';

/**
 * hook_network.js
 *
 * Intercepts native socket connect() calls.
 * Tags suspicious private IP access and dangerous ports (e.g. C2-like behavior).
 */

(async function () {
  const metadata = {
    name: "hook_network",
    category: "network",
    description: "Intercepts native socket connect() calls",
    tags: ["network", "native", "socket"],
    sensitive: true,
    entrypoint: "native"
  };

  const log = createHookLogger(metadata);

  const ntohs = n => ((n & 0xff) << 8) | ((n >> 8) & 0xff);

  const parseSockAddr = (addr) => {
    try {
      const family = addr.readU16();
      if (family === 2) { // AF_INET
        const port = ntohs(addr.add(2).readU16());
        const ip = Array.from({ length: 4 }, (_, i) => addr.add(4 + i).readU8()).join('.');
        return { family, port, ip };
      }
      return { family, port: -1, ip: "<non-IPv4>" };
    } catch (_) {
      return { family: -1, port: -1, ip: "<error>" };
    }
  };

  const isPrivateIP = ip => /^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[0-1])/.test(ip);
  const isDangerousPort = port => [21, 22, 23, 25, 6666, 6667, 1337].includes(port);

  const getBacktrace = ctx => {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .slice(0, 8)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`);
    } catch (_) {
      return ["<no backtrace>"];
    }
  };

  try {
    await safeAttach("connect", {
      onEnter(args) {
        this.ctx = this.context;
        this.sockaddr = args[1];
      },
      onLeave(retval) {
        const parsed = parseSockAddr(this.sockaddr);
        const error = retval.toInt32() < 0;
        const privateIp = isPrivateIP(parsed.ip);
        const dangerousPort = isDangerousPort(parsed.port);
        const suspicious = privateIp || dangerousPort;
        const tags = ["connect"];

        if (privateIp) tags.push("internal_ip");
        if (dangerousPort) tags.push("c2_port");
        if (parsed.family !== 2) tags.push("non_ipv4");

        log(buildEvent({
          metadata,
          action: "connect",
          context: { stack: getBacktrace(this.ctx) },
          args: {
            ip: parsed.ip,
            port: parsed.port,
            family: parsed.family,
            error
          },
          suspicious,
          error,
          tags
        }));

        console.log(`[hook_network] connect() → ${parsed.ip}:${parsed.port} [suspicious=${suspicious}, error=${error}]`);
      }
    }, null, {
      maxRetries: 10,
      retryInterval: 250,
      verbose: true
    });

    log(buildEvent({ metadata, action: "hook_loaded" }));
    send({ type: 'hook_loaded', hook: metadata.name });
    console.log(`[+] ${metadata.name} initialized`);

  } catch (err) {
    console.error(`[hook_network] Failed to attach connect(): ${err}`);
  }
})();
