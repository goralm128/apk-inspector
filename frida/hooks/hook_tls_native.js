'use strict';

(async function () {
  const metadata = {
    name: "hook_tls_native",
    category: "network",
    description: "Hooks SSL_write to monitor encrypted TLS traffic",
    tags: ["native", "tls", "openssl", "ssl", "network", "encrypted"],
    sensitive: true,
    entrypoint: "native"
  };

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

  function captureHash(ptr, length) {
    try {
      if (!ptr.isNull() && length > 0 && length <= 8192) {
        const bytes = Memory.readByteArray(ptr, length);
        return Crypto.digest("sha1", bytes, { encoding: "hex" });
      }
    } catch (_) {}
    return "<unreadable>";
  }

  try {
    const log = await waitForLogger(metadata);

    const sslWriteAddr = Module.findExportByName(null, "SSL_write");

    if (!sslWriteAddr) {
      console.error("[hook_tls_native] Could not find SSL_write");
      return;
    }

    Interceptor.attach(sslWriteAddr, {
      onEnter(args) {
        this.ssl = args[0];
        this.buf = args[1];
        this.len = args[2]?.toInt32?.() ?? 0;
        this.context = this.context;
      },
      onLeave(retval) {
        const sentBytes = retval?.toInt32?.() ?? -1;

        const event = {
          action: "SSL_write",
          bytes_written: sentBytes,
          buffer_sha1: captureHash(this.buf, sentBytes),
          thread: get_thread_name(),
          threadId: Process.getCurrentThreadId(),
          processId: Process.id,
          stack: getBacktrace(this.context),
          tags: ["tls", "encrypted", "ssl"]
        };

        log(event);
        console.log(`[hook_tls_native] SSL_write → ${sentBytes} bytes`);
      }
    });

    send({ type: 'hook_loaded', hook: metadata.name, java: false });
    console.log(`[+] ${metadata.name} initialized`);

  } catch (e) {
    console.error(`[hook_tls_native] Initialization failed: ${e}`);
  }
})();
