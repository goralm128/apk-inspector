'use strict';

/**
 * hook_readwrite.js
 *
 * Hooks native read/write file operations with contextual metadata:
 * file path resolution, stack trace, and buffer hashing (SHA-1).
 */

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

  const MAX_HASH_BYTES = 2048;
  const MAX_SUSPICIOUS_LEN = 4096;
  const hookedActions = ["read", "write"];

  const resolveFdPath = (fd) => {
    try {
      return new File(`/proc/${Process.id}/fd/${fd}`, "r").readlink();
    } catch (_) {
      return "<unknown>";
    }
  };

  const formatBacktrace = (ctx) => {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .slice(0, 10)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`);
    } catch (_) {
      return ["<no backtrace>"];
    }
  };

  for (const fn of hookedActions) {
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
          const suspicious = this.len > MAX_SUSPICIOUS_LEN || /proc|data|cache|tmp|su|sh/i.test(this.path);
          let sha1 = null;

          if (bytes > 0 && bytes <= MAX_HASH_BYTES) {
            try {
              const raw = Memory.readByteArray(this.buf, bytes);
              sha1 = fridaSHA1(raw); // ensure helper exists in your framework
            } catch {
              sha1 = "<unreadable>";
            }
          }

          const direction = this.fn === "write" ? "outbound" : "inbound";
          const tags = ["file_io", direction];
          if (suspicious) tags.push("sensitive_buffer");

          const event = buildEvent({
            metadata,
            action: this.fn,
            context: { stack: formatBacktrace(this.ctx) },
            args: {
              direction,
              fd: this.fd,
              path: this.path,
              bytes,
              buffer_sha1: sha1,
              error: bytes < 0
            },
            suspicious,
            error: bytes < 0,
            tags
          });

          log(event);
          console.log(`[hook_readwrite] ${this.fn}(${this.fd}) → ${bytes} bytes @ ${this.path} [suspicious=${suspicious}]`);
        }
      }, null, {
        maxRetries: 10,
        retryInterval: 250,
        verbose: true
      });

      console.log(`[hook_readwrite] ✓ Hooked ${fn}`);
    } catch (err) {
      console.error(`[hook_readwrite] ✗ Failed to hook ${fn}: ${err}`);
    }
  }

  log(buildEvent({ metadata, action: "hook_loaded" }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized`);
})();
