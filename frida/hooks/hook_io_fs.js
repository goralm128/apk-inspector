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

  function resolveFdPath(fd) {
    try {
      const link = `/proc/${Process.id}/fd/${fd}`;
      return new File(link, "r").readlink();
    } catch (_) {
      return "<unknown>";
    }
  }

  function captureBufferHash(ptr, length) {
    try {
      if (length > 0 && length <= 2048) {
        const bytes = Memory.readByteArray(ptr, length);
        return Crypto.digest("sha1", bytes, { encoding: "hex" });
      }
    } catch (_) {
      return "<unreadable>";
    }
    return null;
  }

  try {
    const log = await waitForLogger(metadata);

    runWhenJavaIsReady(() => {
      const functions = ["read", "write"];

      for (const name of functions) {
        safeAttach(name, {
          onEnter(args) {
            this.name = name;
            this.fd = args[0]?.toInt32?.() ?? -1;
            this.buf = args[1];
            this.len = args[2]?.toInt32?.() ?? 0;
            this.path = resolveFdPath(this.fd);
            this.context = this.context;
          },
          onLeave(retval) {
            const bytes = retval?.toInt32?.() ?? -1;
            const suspicious = this.len > 4096 || /proc|cache|tmp|su|sh/i.test(this.path);

            const event = {
              action: this.name,
              direction: this.name === "write" ? "outbound" : "inbound",
              fd: this.fd,
              file_path: this.path,
              bytes,
              error: bytes < 0,
              suspicious,
              thread: get_thread_name(),
              threadId: Process.getCurrentThreadId(),
              processId: Process.id,
              stack: Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress)
                .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`),
              tags: ["fs"].concat(suspicious ? ["suspicious_path"] : [])
            };

            if (bytes > 0 && bytes <= 2048) {
              event.buffer_sha1 = captureBufferHash(this.buf, bytes);
            }

            console.log(`[hook_io_fs] ${this.name}(${this.fd}) → ${bytes} bytes @ ${this.path}`);
            log(event);
          }
        }, null, {
          maxRetries: 10,
          retryInterval: 250,
          verbose: true
        }).then(() => {
          console.log(`[hook_io_fs] Hooked ${name}`);
        }).catch(err => {
          console.error(`[hook_io_fs] Failed to hook ${name}: ${err}`);
        });
      }

      send({ type: 'hook_loaded', hook: metadata.name, java: false });
      console.log(`[+] ${metadata.name} initialized`);
    });

  } catch (err) {
    console.error(`[hook_io_fs] Logger setup failed: ${err}`);
  }
})();
