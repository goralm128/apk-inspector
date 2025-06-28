'use strict';

/**
 * hook_tls_native.js
 *
 * Hooks OpenSSL's SSL_write and SSL_get_peer_certificate to monitor encrypted traffic.
 * Captures SHA1 of outbound buffers and TLS cert fingerprint.
 */

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

  const log = await waitForLogger(metadata);

  const getBacktrace = (ctx) => {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .slice(0, BACKTRACE_DEPTH)
        .map(DebugSymbol.fromAddress)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`)
        .join("\n");
    } catch (_) {
      return "<no stack>";
    }
  };

  const captureHash = (ptr, length) => {
    if (!ptr || ptr.isNull() || length <= 0 || length > MAX_CAPTURE_BYTES) return "<unreadable>";
    try {
      const bytes = Memory.readByteArray(ptr, length);
      return Crypto.digest("sha1", bytes, { encoding: "hex" });
    } catch (_) {
      return "<unreadable>";
    }
  };

  // Hook SSL_write
  await safeAttach("SSL_write", {
    onEnter(args) {
      this.ssl = args[0];
      this.buf = args[1];
      this.len = args[2]?.toInt32?.() ?? 0;
      this.ctx = this.context;
    },
    onLeave(retval) {
      const bytes = retval?.toInt32?.() ?? -1;

      const event = buildEvent({
        metadata,
        action: "SSL_write",
        args: {
          bytes,
          buffer_sha1: captureHash(this.buf, bytes),
          error: bytes < 0
        },
        context: { stack: getBacktrace(this.ctx) },
        suspicious: bytes > MAX_CAPTURE_BYTES,
        tags: metadata.tags
      });

      log(event);
      console.log(`[hook_tls_native] SSL_write → ${bytes} bytes`);
    }
  });

  // Hook SSL_get_peer_certificate if available
  try {
    const sslLib = Module.findBaseAddress("libssl.so");
    if (sslLib) {
      const certFn = Module.findExportByName("libssl.so", "SSL_get_peer_certificate");
      const x509DerFn = Module.findExportByName("libssl.so", "i2d_X509");

      if (certFn && x509DerFn) {
        const toDER = new NativeFunction(x509DerFn, 'int', ['pointer', 'pointer']);

        Interceptor.attach(certFn, {
          onLeave(retval) {
            if (!retval.isNull()) {
              try {
                const len = toDER(retval, NULL);
                if (len > 0) {
                  const derBuf = Memory.alloc(len);
                  toDER(retval, derBuf);
                  const der = Memory.readByteArray(derBuf, len);
                  const sha1 = Crypto.digest("sha1", der, { encoding: "hex" });

                  log(buildEvent({
                    metadata,
                    action: "SSL_get_peer_certificate",
                    args: { sha1 },
                    context: {}
                  }));

                  console.log(`[hook_tls_native] cert fingerprint: ${sha1}`);
                }
              } catch (e) {
                console.error(`[hook_tls_native] cert parse failed: ${e}`);
              }
            }
          }
        });

        console.log(`[hook_tls_native] Hooked SSL_get_peer_certificate`);
      }
    }
  } catch (e) {
    console.error(`[hook_tls_native] Cert hook error: ${e}`);
  }

  log(buildEvent({ metadata, action: "hook_loaded" }));
  send({ type: "hook_loaded", hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized`);
})();
