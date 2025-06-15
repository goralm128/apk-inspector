'use strict';

const metadata = {
  name: "hook_socket_io",
  category: "network",
  description: "Hooks native socket operations with C2/IP/port blacklisting",
  tags: ["native", "socket", "network", "threat"],
  sensitive: true
};

// Blacklists
const dangerousPorts = new Set([23, 80, 443, 502, 5037, 5555, 4444, 8080, 8443, 2323]);
const maliciousIPs = new Set([
  "192.99.251.51",
  "31.170.161.216",
  "95.211.216.148",
  "27.255.79.225",
  "121.42.149.52",
  "103.207.85.8",
  "85.101.222.222",
  "62.204.41.189",
  "93.48.80.252"
]);

// Map FD → endpoint
const fdInfo = {};

function isSuspicious(ip, port) {
  return {
    suspicious_ip: maliciousIPs.has(ip),
    dangerous_port: dangerousPorts.has(port)
  };
}

function resolvePeer(fd) {
  try {
    const sockaddr = Memory.alloc(16);
    const lenPtr = Memory.alloc(Process.pointerSize);
    lenPtr.writeUInt(16);

    const ret = Module.getExportByName(null, "getpeername")(fd, sockaddr, lenPtr);
    if (ret !== 0) return null;

    const family = sockaddr.readU16();
    if (family !== 2) return null; // AF_INET only
    const port = ntohs(sockaddr.add(2).readU16());
    const ipBytes = sockaddr.add(4).readByteArray(4);
    const ip = Array.from(new Uint8Array(ipBytes)).join(".");
    return { ip, port };
  } catch (e) {
    return null;
  }
}

function ntohs(n) {
  return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
}

(async () => {
  const log = await waitForLogger(metadata);

  // Hook connect() to record fd → endpoint
  try {
    const connAddr = Module.getExportByName(null, "connect");
    Interceptor.attach(connAddr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
      },
      onLeave(ret) {
        const info = resolvePeer(this.fd);
        if (info) {
          fdInfo[this.fd] = info;
          const flags = isSuspicious(info.ip, info.port);
          log({
            action: "connect",
            fd: this.fd,
            ip: info.ip,
            port: info.port,
            ...flags
          });
        }
      }
    });
    console.log(`[${metadata.name}] Hooked connect`);
  } catch (e) {
    console.error(`[${metadata.name}] Failed connect hook: ${e}`);
  }

  // Attach generic socket functions
  const funcs = ["send", "recv", "sendto", "recvfrom"];
  for (const fn of funcs) {
    try {
      const addr = Module.getExportByName(null, fn);
      Interceptor.attach(addr, {
        onEnter(args) {
          this.fd = args[0].toInt32();
          this.name = fn;
        },
        onLeave(retval) {
          const info = fdInfo[this.fd];
          let ip = null, port = null;
          let flags = { suspicious_ip: false, dangerous_port: false };
          if (info) {
            ip = info.ip;
            port = info.port;
            flags = isSuspicious(ip, port);
          }
          log({
            action: this.name,
            fd: this.fd,
            bytes: retval.toInt32(),
            ip,
            port,
            ...flags
          });
        }
      });
      console.log(`[${metadata.name}] Hooked ${fn}`);
    } catch (e) {
      console.error(`[${metadata.name}] Failed hooking ${fn}: ${e}`);
    }
  }

  send({ type: 'hook_loaded', hook: metadata.name, java: false });
  console.log(`[+] ${metadata.name} initialized`);
})();
