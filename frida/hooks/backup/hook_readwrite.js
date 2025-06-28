'use strict';

(async function () {
  const metadata = {
    name: "hook_readwrite",
    category: "filesystem",
    description: "Hooks native read/write file operations with enhanced context",
    tags: ["native", "read", "write", "fs", "buffer"],
    sensitive: true,
    entrypoint: "native"
  };

  const log = createHookLogger(metadata);
  const actions = ["read", "write"];
  const MAX_HASH_BYTES = 2048;
  const MAX_SUSPICIOUS_LEN = 4096;

  function resolveFdPath(fd) {
    try {
      return new File(`/proc/${Process.id}/fd/${fd}`, "r").readlink();
    } catch {
      return "<unknown>";
    }
  }

  function getBacktrace(ctx) {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .slice(0, 10)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`);
    } catch {
      return ["<no backtrace>"];
    }
  }

  for (const fn of actions) {
    try {
      await safeAttach(fn, {
        onEnter(args) {
          this.fn = fn;
          this.fd = args[0]?.toInt32?.() ?? -1;
          this.buf = args[1];
          this.len = args[2]?.toInt32?.() ?? 0;
          this.path = normalizePath(resolveFdPath(this.fd));
          this.ctx = this.context;
        },
        onLeave(retval) {
          const bytes = retval?.toInt32?.() ?? -1;
          let sha1 = null;

          const suspicious = this.len > MAX_SUSPICIOUS_LEN || /proc|data|cache|tmp|su|sh/i.test(this.path);

          if (bytes > 0 && bytes <= MAX_HASH_BYTES) {
            try {
              const raw = Memory.readByteArray(this.buf, bytes);
              sha1 = fridaSHA1(raw); // ensure this helper exists
            } catch {
              sha1 = "<unreadable>";
            }
          }

          const event = buildEvent({
            metadata,
            action: this.fn,
            context: { stack: getBacktrace(this.ctx) },
            args: {
              direction: this.fn === "write" ? "outbound" : "inbound",
              fd: this.fd,
              path: this.path,
              bytes,
              buffer_sha1: sha1,
              error: bytes < 0
            },
            suspicious,
            error: bytes < 0
          });

          log(event);
          console.log(`[${metadata.name}] ${this.fn}(${this.fd}) → ${bytes} bytes @ ${this.path}`);
        }
      }, null, {
        maxRetries: 10,
        retryInterval: 250,
        verbose: true
      });

      console.log(`[${metadata.name}] ✓ Hooked ${fn}`);
    } catch (err) {
      console.error(`[${metadata.name}] ✗ Failed to hook ${fn}: ${err}`);
    }
  }

  log(buildEvent({ metadata, action: "hook_loaded", args: {} }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized`);
})();
