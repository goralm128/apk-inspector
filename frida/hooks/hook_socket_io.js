'use strict';

(async function () {
  const metadata = {
    name: "hook_socket_io",
    category: "network",
    description: "Hooks native socket operations with C2/IP/port blacklisting",
    tags: ["native", "socket", "network", "threat"],
    sensitive: true,
    entrypoint: "native"
  };

  const BLACKLISTED_PORTS = new Set([23, 80, 443, 502, 5037, 5555, 4444, 8080, 8443, 2323]);
  const BLACKLISTED_IPS = new Set([
    "192.99.251.51", "31.170.161.216", "95.211.216.148", "27.255.79.225",
    "121.42.149.52", "103.207.85.8", "85.101.222.222", "62.204.41.189", "93.48.80.252"
  ]);

  const fdMap = {};

  function ntohs(n) {
    return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
  }

  function resolvePeer(fd) {
    try {
      const sockaddr = Memory.alloc(16);
      const lenPtr = Memory.alloc(Process.pointerSize);
      lenPtr.writeU32(16);

      const getpeername = new NativeFunction(Module.getExportByName(null, "getpeername"), "int", ["int", "pointer", "pointer"]);
      const result = getpeername(fd, sockaddr, lenPtr);
      if (result !== 0) return null;

      const family = sockaddr.readU16();
      if (family !== 2) return null;

      const port = ntohs(sockaddr.add(2).readU16());
      const ip = [
        sockaddr.add(4).readU8(),
        sockaddr.add(5).readU8(),
        sockaddr.add(6).readU8(),
        sockaddr.add(7).readU8()
      ].join(".");

      return { ip, port };
    } catch (_) {
      return null;
    }
  }

  function tagSuspicious(ip, port) {
    return {
      suspicious_ip: BLACKLISTED_IPS.has(ip),
      dangerous_port: BLACKLISTED_PORTS.has(port)
    };
  }

  try {
    const log = await waitForLogger(metadata);

    // Hook connect()
    await safeAttach("connect", {
      onEnter(args) {
        this.fd = args[0]?.toInt32?.() ?? -1;
      },
      onLeave(retval) {
        if (retval?.toInt32?.() === 0 && this.fd !== -1) {
          const peer = resolvePeer(this.fd);
          if (peer) {
            fdMap[this.fd] = peer;

            const tags = tagSuspicious(peer.ip, peer.port);
            const event = {
              action: "connect",
              fd: this.fd,
              ip: peer.ip,
              port: peer.port,
              ...tags,
              thread: get_thread_name(),
              threadId: Process.getCurrentThreadId(),
              processId: Process.id
            };

            console.log(`[hook_socket_io] connect(${this.fd}) → ${peer.ip}:${peer.port}`);
            log(event);
          }
        }
      }
    }, null, {
      maxRetries: 8,
      retryInterval: 250,
      verbose: true
    });

    // Hook send, recv, sendto, recvfrom
    const funcs = ["send", "recv", "sendto", "recvfrom"];
    for (const fn of funcs) {
      await safeAttach(fn, {
        onEnter(args) {
          this.fd = args[0]?.toInt32?.() ?? -1;
          this.fn = fn;
        },
        onLeave(retval) {
          const peer = fdMap[this.fd] ?? resolvePeer(this.fd);
          const ip = peer?.ip || "<unknown>";
          const port = peer?.port || -1;
          const tags = tagSuspicious(ip, port);

          const event = {
            action: this.fn,
            fd: this.fd,
            ip,
            port,
            bytes: retval?.toInt32?.() ?? -1,
            ...tags,
            thread: get_thread_name(),
            threadId: Process.getCurrentThreadId(),
            processId: Process.id
          };

          log(event);
          console.log(`[hook_socket_io] ${this.fn}(${this.fd}) → ${event.bytes} bytes to ${ip}:${port}`);
        }
      }, null, {
        maxRetries: 8,
        retryInterval: 250,
        verbose: true
      });

      console.log(`[hook_socket_io] Hooked ${fn}`);
    }

    send({ type: "hook_loaded", hook: metadata.name, java: false });
    console.log(`[+] ${metadata.name} initialized`);

  } catch (e) {
    console.error(`[hook_socket_io] Logger setup or initialization failed: ${e}`);
  }
})();
