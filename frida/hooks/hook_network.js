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

  // --- Utility functions ---
  function ntohs(n) {
    return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
  }

  function parseSockAddr(addr) {
    try {
      const family = addr.readU16();
      if (family === 2) { // AF_INET
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
    } catch (_) {
      return { family: -1, port: -1, ip: "<error>" };
    }
  }

  function isSuspiciousIP(ip) {
    return /^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[0-1])/.test(ip);
  }

  function isDangerousPort(port) {
    return [21, 22, 23, 25, 6666, 6667, 1337].includes(port);
  }

  try {
    const log = await waitForLogger(metadata);

    await safeAttach("connect", {
      onEnter(args) {
        try {
          const sockaddr = args[1];
          const parsed = parseSockAddr(sockaddr);
          const suspicious = isSuspiciousIP(parsed.ip);
          const dangerous = isDangerousPort(parsed.port);

          const tags = ["network"];
          if (suspicious) tags.push("suspicious_ip");
          if (dangerous) tags.push("dangerous_port");

          const event = {
            action: "connect",
            ip: parsed.ip,
            port: parsed.port,
            family: parsed.family,
            suspicious,
            dangerous,
            thread: get_thread_name(),
            threadId: Process.getCurrentThreadId(),
            processId: Process.id,
            tags
          };

          console.log(`[hook_network] connect() → ${parsed.ip}:${parsed.port}`);
          log(event);

        } catch (err) {
          console.error(`[hook_network] Error parsing sockaddr: ${err}`);
        }
      }
    }, null, {
      maxRetries: 8,
      retryInterval: 300,
      verbose: true
    });

    send({ type: 'hook_loaded', hook: metadata.name, java: false });
    console.log(`[+] ${metadata.name} initialized`);

  } catch (e) {
    console.error(`[hook_network] Logger setup or hook initialization failed: ${e}`);
  }
})();
