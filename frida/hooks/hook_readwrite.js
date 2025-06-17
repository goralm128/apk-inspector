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

  const actions = ["read", "write"];

  function resolveFdPath(fd) {
    try {
      const path = `/proc/${Process.id}/fd/${fd}`;
      return new File(path, "r").readlink();
    } catch (_) {
      return "<unknown>";
    }
  }

  function computeSha1(bytes) {
    try {
      return Crypto.digest("sha1", bytes, { encoding: "hex" });
    } catch (_) {
      return "<hash-failed>";
    }
  }

  function getBacktrace(context) {
    try {
      return Thread.backtrace(context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"} @ ${sym.address}`)
        .join("\n");
    } catch (_) {
      return "N/A";
    }
  }

  try {
    const log = await waitForLogger(metadata);

    runWhenJavaIsReady(() => {
      actions.forEach(fn => {
        safeAttach(fn, {
          onEnter(args) {
            this.fn = fn;
            this.fd = args[0]?.toInt32?.() ?? -1;
            this.buf = args[1];
            this.len = args[2]?.toInt32?.() ?? 0;
            this.context = this.context;
            this.path = resolveFdPath(this.fd);
          },
          onLeave(retval) {
            const bytes = retval?.toInt32?.() ?? -1;
            const suspicious = this.len > 4096 || /proc|data|cache|tmp|su|sh/i.test(this.path);

            const event = {
              action: this.fn,
              direction: this.fn === "write" ? "outbound" : "inbound",
              fd: this.fd,
              file_path: this.path,
              bytes,
              error: bytes < 0,
              suspicious,
              thread: get_thread_name(),
              threadId: Process.getCurrentThreadId(),
              processId: Process.id,
              stack: getBacktrace(this.context),
              tags: ["fs", "readwrite"]
            };

            if (this.fn === "write" && bytes > 0 && bytes <= 2048) {
              try {
                const raw = Memory.readByteArray(this.buf, bytes);
                event.buffer_sha1 = computeSha1(raw);
              } catch (_) {
                event.buffer_sha1 = "<unreadable>";
              }
            }

            log(event);
            console.log(`[hook_readwrite] ${this.fn}(${this.fd}) → ${bytes} bytes @ ${this.path}`);
          }
        }, null, {
          maxRetries: 8,
          retryInterval: 250,
          verbose: true
        }).then(() => {
          console.log(`[hook_readwrite] Hooked ${fn}`);
        }).catch(err => {
          console.error(`[hook_readwrite] Failed to hook ${fn}: ${err}`);
        });
      });

      send({ type: 'hook_loaded', hook: metadata.name, java: false });
      console.log(`[+] ${metadata.name} initialized`);
    });

  } catch (e) {
    console.error(`[hook_readwrite] Logger setup failed: ${e}`);
  }
})();
