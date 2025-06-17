'use strict';

(function () {

  // =====================[ Java Context Checker ]=====================
  globalThis.isJavaAvailable = function () {
    try {
      return typeof Java !== 'undefined' && Java.available;
    } catch (_) {
      return false;
    }
  };

  // =====================[ Async Java Ready Waiter ]=====================
  globalThis.runWhenJavaIsReady = function ({
    retryInterval = 500,
    maxRetries = 50,
    verbose = true
  } = {}) {
    return new Promise((resolve, reject) => {
      let attempts = 0;

      const tryCheck = () => {
        if (typeof Java === 'undefined') {
          if (verbose) console.warn("[runWhenJavaIsReady] Java is undefined.");
          return retry();
        }

        if (Java.available) {
          try {
            Java.perform(() => {
              if (verbose) console.log("[runWhenJavaIsReady] Java.perform succeeded.");
              resolve();
            });
          } catch (e) {
            console.error("[runWhenJavaIsReady] Java.perform error:", e);
            reject(e);
          }
        } else {
          retry();
        }
      };

      const retry = () => {
        if (++attempts <= maxRetries) {
          if (verbose) console.log(`[runWhenJavaIsReady] Retrying... (${attempts}/${maxRetries})`);
          setTimeout(tryCheck, retryInterval);
        } else {
          const msg = "[runWhenJavaIsReady] Gave up waiting for Java VM.";
          console.error(msg);
          reject(new Error(msg));
        }
      };

      tryCheck();
    });
  };

  // =====================[ Logger Factory ]=====================
  globalThis.createHookLogger = function ({
    hook,
    category,
    tags = [],
    description = "",
    sensitive = false
  }) {
    const metadata = { name: hook, category, tags, description, sensitive };
    return function logEvent(payload) {
      try {
        const event = {
          ...payload,
          hook: metadata.name,
          metadata,
          timestamp: new Date().toISOString(),
          threadId: Process.getCurrentThreadId()
        };
        if (!payload.hook) payload.hook = metadata.name;
        send(event);
      } catch (e) {
        console.error(`[createHookLogger] Failed for ${hook}: ${e}`);
      }
    };
  };

  globalThis.waitForLogger = function (metadata, timeout = 5000, interval = 100) {
    return new Promise((resolve, reject) => {
      const start = Date.now();

      const check = () => {
        if (typeof globalThis.createHookLogger === 'function') {
          console.log(`[waitForLogger] Logger ready for ${metadata.name}`);
          const logger = createHookLogger(metadata);
          resolve(logger);
        } else if (Date.now() - start < timeout) {
          setTimeout(check, interval);
        } else {
          const msg = `[waitForLogger] Timeout waiting for createHookLogger (${metadata.name})`;
          console.error(msg);
          reject(new Error(msg));
        }
      };

      check();
    });
  };

  // =====================[ Thread / Stack Utilities ]=====================
  globalThis.get_thread_name = function () {
    if (!isJavaAvailable()) return "Java not available";
    try {
      return Java.use("java.lang.Thread").currentThread().getName();
    } catch (_) {
      return "unknown-thread";
    }
  };

  globalThis.get_java_stack = function () {
    if (!isJavaAvailable()) return "Java not available";
    try {
      return Java.use("java.lang.Exception").$new().getStackTrace()
        .map(frame => frame.toString())
        .join('\n');
    } catch (_) {
      return "N/A";
    }
  };

  // =====================[ Memory and Digest Utils ]=====================
  globalThis.readBytesSafe = function (ptr, len) {
    try {
      if (!ptr || ptr.isNull() || len <= 0) return null;
      return Memory.readByteArray(ptr, len);
    } catch (_) {
      return null;
    }
  };

  globalThis.toHex = function (array) {
    if (!array || typeof array !== 'object' || !('length' in array)) return '';
    return Array.prototype.map.call(array, x => ('00' + x.toString(16)).slice(-2)).join('');
  };

  globalThis.fridaSHA1 = function (bytes) {
    try {
      return Crypto.digest("sha1", bytes, { encoding: "hex" });
    } catch (_) {
      return "<sha1-failed>";
    }
  };

  // =====================[ Safe Native Hooker ]=====================
  globalThis.safeAttach = function safeAttach(
    funcName,
    callbacks,
    moduleName = null,
    {
      initialDelay = 0,
      maxRetries = 10,
      retryInterval = 200,
      verbose = true
    } = {}
  ) {
    return new Promise((resolve, reject) => {
      let attempts = 0;

      const tryHook = () => {
        let addr = null;
        try {
          addr = Module.findExportByName(moduleName, funcName);
        } catch (e) {
          return retry(`[safeAttach] Module lookup failed for ${funcName}: ${e}`);
        }

        if (!addr) {
          return retry(`[safeAttach] ${funcName} not found in ${moduleName || "default module"}`);
        }

        if (typeof Interceptor?.attach !== 'function') {
          return retry(`[safeAttach] Interceptor.attach not available`);
        }

        try {
          Interceptor.attach(addr, callbacks);
          if (verbose) console.log(`[safeAttach] Hooked ${funcName} at ${addr}`);
          resolve(addr);
        } catch (e) {
          reject(`[safeAttach] Attaching to ${funcName} failed: ${e}`);
        }
      };

      const retry = (log) => {
        if (++attempts < maxRetries) {
          if (verbose) console.warn(`${log}, retrying (${attempts}/${maxRetries})`);
          setTimeout(tryHook, retryInterval);
        } else {
          const msg = `[safeAttach] Giving up on ${funcName} after ${maxRetries} attempts`;
          console.error(msg);
          reject(msg);
        }
      };

      setTimeout(tryHook, initialDelay);
    });
  };

  // =====================[ Native Symbol Resolver ]=====================
  globalThis.resolveNativeExport = function (funcName, moduleName = null) {
    try {
      return Module.findExportByName(moduleName, funcName);
    } catch (_) {
      return null;
    }
  };

  // =====================[ C2 Pattern Checker ]=====================
  globalThis.isSensitiveNativeFunction = function (name) {
    if (typeof name !== 'string') return false;
    const risky = ["system", "exec", "dlopen", "fork", "popen", "CreateProcess"];
    return risky.includes(name.toLowerCase());
  };

  // =====================[ Custom Event Emitter ]=====================
  globalThis.send_event = function (data, context = {}) {
    try {
      const payload = {
        ...data,
        ...context,
        timestamp: new Date().toISOString()
      };
      send(payload);
    } catch (e) {
      console.error(`[send_event] Failed: ${e}`);
    }
  };

  // =====================[ Initialization Signal ]=====================
  try {
    if (!globalThis._fridaHelpersInitialized) {
      globalThis._fridaHelpersInitialized = true;

      runWhenJavaIsReady().then(() => {
        send({
          type: 'frida_helpers_loaded',
          hook: "frida_helpers",
          category: 'system',
          tags: ["init"],
          timestamp: new Date().toISOString(),
          globals: {
            runWhenJavaIsReady: typeof runWhenJavaIsReady === 'function',
            createHookLogger: typeof createHookLogger === 'function',
            isJavaAvailable: true
          }
        });
      }).catch((e) => {
        console.error("[frida_helpers] Could not initialize Java:", e);
      });
    }
  } catch (e) {
    console.error("[frida_helpers] Initialization failed:", e);
  }

})();
