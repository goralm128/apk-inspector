'use strict';

(async function () {
  const metadata = {
    name: "hook_io_fs",
    category: "filesystem",
    description: "Hooks native read/write file operations",
    tags: ["native", "read", "write", "fs"],
    sensitive: true,
    entrypoint: "native"
  };

  const resolveFdPath = (fd) => {
    try {
      const link = `/proc/${Process.id}/fd/${fd}`;
      return new File(link, "r").readlink();
    } catch (_) {
      return "<unknown>";
    }
  };

  const captureBufferHash = (ptr, length) => {
    try {
      if (length > 0 && length <= 2048) {
        const bytes = Memory.readByteArray(ptr, length);
        return Crypto.digest("sha1", bytes, { encoding: "hex" });
      }
    } catch (_) {}
    return null;
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

    const hookReadOrWrite = async (fnName) => {
      await safeAttach(fnName, {
        onEnter(args) {
          this.fnName = fnName;
          this.fd = args?.[0]?.toInt32?.() ?? -1;
          this.buf = args?.[1];
          this.len = args?.[2]?.toInt32?.() ?? 0;
          this.path = resolveFdPath(this.fd);
          this.ctx = this.context;
        },
        onLeave(retval) {
          const bytes = retval?.toInt32?.() ?? -1;
          const suspicious = this.len > 4096 || /proc|cache|tmp|su|sh/i.test(this.path);
          const hash = (bytes > 0 && bytes <= 2048)
            ? captureBufferHash(this.buf, bytes)
            : undefined;

          log(buildEvent({
            metadata,
            action: this.fnName,
            context: { stack: formatBacktrace(this.ctx) },
            args: {
              direction: this.fnName === "write" ? "outbound" : "inbound",
              fd: this.fd,
              file_path: this.path,
              bytes,
              error: bytes < 0,
              suspicious,
              buffer_sha1: hash
            },
            tags: suspicious ? metadata.tags.concat("suspicious_path") : metadata.tags
          }));

          console.log(`[hook_io_fs] ${this.fnName}(${this.fd}) → ${bytes} bytes @ ${this.path}`);
        }
      }, null, {
        maxRetries: 10,
        retryInterval: 250,
        verbose: true
      });

      console.log(`[hook_io_fs] Hooked ${fnName}`);
    };

    await hookReadOrWrite("read");
    await hookReadOrWrite("write");

    log(buildEvent({ metadata, action: "hook_loaded" }));
    send({ type: 'hook_loaded', hook: metadata.name });
    console.log(`[+] ${metadata.name} initialized`);
  } catch (err) {
    console.error(`[hook_io_fs] Initialization failed: ${err}`);
  }
})();
