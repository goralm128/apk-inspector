'use strict';

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

  function ntohs(n) {
    return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
  }

  function parseSockAddr(addr) {
    try {
      const family = addr.readU16();
      if (family === 2) { // AF_INET
        const port = ntohs(addr.add(2).readU16());
        const ip = Array.from({ length: 4 }, (_, i) => addr.add(4 + i).readU8()).join('.');
        return { family, port, ip };
      }
      return { family, port: -1, ip: "<non-IPv4>" };
    } catch {
      return { family: -1, port: -1, ip: "<error>" };
    }
  }

  function isPrivateIP(ip) {
    return /^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[0-1])/.test(ip);
  }

  function isDangerousPort(port) {
    return [21, 22, 23, 25, 6666, 6667, 1337].includes(port);
  }

  function getBacktrace(ctx) {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`);
    } catch {
      return ["<no backtrace>"];
    }
  }

  try {
    await safeAttach("connect", {
      onEnter(args) {
        this.ctx = this.context;
        this.sockaddr = args[1];
      },
      onLeave(retval) {
        try {
          const parsed = parseSockAddr(this.sockaddr);
          const privateIp = isPrivateIP(parsed.ip);
          const dangerous = isDangerousPort(parsed.port);
          const error = retval.toInt32() < 0;

          log(buildEvent({
            metadata,
            action: "connect",
            context: { stack: getBacktrace(this.ctx) },
            args: {
              ip: parsed.ip,
              port: parsed.port,
              family: parsed.family,
              suspicious: privateIp,
              dangerous
            },
            suspicious: privateIp || dangerous,
            error
          }));

          console.log(`[hook_network] connect() → ${parsed.ip}:${parsed.port} (${error ? "ERROR" : "OK"})`);
        } catch (e) {
          console.error(`[hook_network] Error parsing sockaddr: ${e}`);
        }
      }
    }, null, {
      maxRetries: 10,
      retryInterval: 250,
      verbose: true
    });

    log(buildEvent({ metadata, action: "hook_loaded", args: {} }));
    send({ type: 'hook_loaded', hook: metadata.name });
    console.log(`[+] ${metadata.name} initialized`);

  } catch (err) {
    console.error(`[hook_network] Failed to attach connect(): ${err}`);
  }
})();
