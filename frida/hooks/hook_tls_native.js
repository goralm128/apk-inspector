'use strict';

(async function () {
  const metadata = {
    name: "hook_tls_native",
    category: "network",
    description: "Monitors encrypted traffic via SSL_write + SSL_get_peer_certificate",
    tags: ["native", "tls", "openssl", "ssl", "network", "encrypted"],
    sensitive: true,
    entrypoint: "native"
  };

  const BACKTRACE_DEPTH = 50;
  const MAX_CAPTURE_BYTES = 8192;

  function getBacktrace(ctx) {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .slice(0, BACKTRACE_DEPTH)
        .map(DebugSymbol.fromAddress)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`)
        .join("\n");
    } catch (_) {
      return "<no stack>";
    }
  }

  function captureHash(ptr, length) {
    if (!ptr || ptr.isNull() || length <= 0 || length > MAX_CAPTURE_BYTES) {
      return "<unreadable>";
    }
    try {
      const bytes = Memory.readByteArray(ptr, length);
      return Crypto.digest("sha1", bytes, { encoding: "hex" });
    } catch (_) {
      return "<unreadable>";
    }
  }

  const log = await waitForLogger(metadata);

  // Hook SSL_write
  await safeAttach("SSL_write", {
    onEnter(args) {
      this.ssl = args[0];
      this.buf = args[1];
      this.len = args[2]?.toInt32?.() ?? 0;
      this.context = this.context;
    },
    onLeave(retval) {
      const bytesWritten = retval?.toInt32?.() ?? -1;

      const event = {
        hook: metadata.name,
        action: "SSL_write",
        bytes_written: bytesWritten,
        buffer_sha1: captureHash(this.buf, bytesWritten),
        error: bytesWritten < 0,
        suspicious: bytesWritten > MAX_CAPTURE_BYTES,
        thread: get_thread_name(),
        threadId: Process.getCurrentThreadId(),
        processId: Process.id,
        stack: getBacktrace(this.context),
        tags: metadata.tags,
        metadata,
        timestamp: new Date().toISOString()
      };

      log(event);
      console.log(`[${metadata.name}] SSL_write → ${bytesWritten} bytes`);
    }
  });

  // Optionally hook SSL_get_peer_certificate
  try {
    const sslLib = Module.findBaseAddress("libssl.so");
    if (sslLib) {
      const SSL_get_peer_certificate = Module.findExportByName("libssl.so", "SSL_get_peer_certificate");
      if (SSL_get_peer_certificate) {
        Interceptor.attach(SSL_get_peer_certificate, {
          onLeave(retval) {
            if (!retval.isNull()) {
              try {
                const certPtr = retval;
                const x509ToDer = new NativeFunction(Module.findExportByName("libssl.so", "i2d_X509"), 'int', ['pointer', 'pointer']);
                const len = x509ToDer(certPtr, NULL);
                if (len > 0) {
                  const derBuf = Memory.alloc(len);
                  x509ToDer(certPtr, derBuf);
                  const derBytes = Memory.readByteArray(derBuf, len);
                  const fingerprint = Crypto.digest("sha1", derBytes, { encoding: "hex" });
                  log(buildEvent({
                    metadata,
                    action: "SSL_get_peer_certificate",
                    args: { sha1: fingerprint },
                    context: {}
                  }));
                  console.log(`[${metadata.name}] cert fingerprint: ${fingerprint}`);
                }
              } catch (e) {
                console.error(`[${metadata.name}] SSL_get_peer_certificate error: ${e}`);
              }
            }
          }
        });
        console.log(`[${metadata.name}] Hooked SSL_get_peer_certificate`);
      }
    }
  } catch (e) {
    console.error(`[${metadata.name}] Failed to hook certificate API: ${e}`);
  }
  log(buildEvent({ metadata, action: "hook_loaded", args: {} }));
  send({ type: "hook_loaded", hook: metadata.name, java: false });
  console.log(`[+] ${metadata.name} initialized`);
})();
