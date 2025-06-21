'use strict';

(function () {
  const fallbackLibs = ['libc.so', 'libdl.so', 'libc.so.6', 'libbionic.so', 'libc_malloc_debug.so'];

  // ───── Java VM Utilities ───────────────────────────
  globalThis.isJavaAvailable = () => {
    try { return typeof Java !== 'undefined' && Java.available; }
    catch { return false; }
  };

  globalThis.runWhenJavaIsReady = ({
    retryInterval = 500,
    maxRetries = 30,
    verbose = true
  } = {}) => {
    if (globalThis._javaReadyPromise) return globalThis._javaReadyPromise;

    globalThis._javaReadyPromise = new Promise((resolve, reject) => {
      let attempts = 0;

      const tryPerform = () => {
        if (!isJavaAvailable()) {
          return retry('[JavaCheck] Java not yet available');
        }

        try {
          Java.perform(() => {
            verbose && console.log('[JavaCheck] Java.perform() successful');
            resolve();
          });
        } catch (err) {
          retry(`[JavaCheck] perform failed: ${err}`);
        }
      };

      const retry = msg => {
        if (++attempts <= maxRetries) {
          verbose && console.warn(`${msg}, retry #${attempts}`);
          const backoff = Math.min(retryInterval * Math.pow(1.5, attempts), 5000);
          setTimeout(tryPerform, backoff);
        } else {
          const finalMsg = '[JavaCheck] timed out';
          verbose && console.error(finalMsg);
          reject(finalMsg);
        }
      };

      tryPerform();
    });

    return globalThis._javaReadyPromise;
  };

  globalThis.maybeRunJavaHook = (cb, metadata = {}) => {
    if (metadata.entrypoint?.toLowerCase() === 'java') {
      return runWhenJavaIsReady().then(cb).catch(err => console.error(err));
    }
    return cb();
  };

  globalThis.ifJava = fn => isJavaAvailable() ? fn() : undefined;

  // ───── Logger Utilities ─────────────────────────────
  globalThis.createHookLogger = metadata => {
    return event => {
      event = event || {};
      event.hook = event.hook || metadata.name || 'unknown';
      event.entrypoint = event.entrypoint || metadata.entrypoint || 'native';
      event.timestamp = event.timestamp || new Date().toISOString();
      event.tags = Array.from(new Set([...(metadata.tags || []), ...(event.tags || [])]));
      event.sensitive = metadata.sensitive ?? false;
      send(event);
    };
  };

  globalThis.waitForLogger = async metadata => {
    return Promise.resolve(createHookLogger(metadata));
  };

  // ───── Event Builder ────────────────────────────────
  globalThis.buildEvent = ({
    metadata = {},
    action = null,
    context = {},
    args = {},
    error = false,
    suspicious = false
  } = {}) => ({
    timestamp: new Date().toISOString(),
    hook: metadata.name || 'unknown',
    entrypoint: metadata.entrypoint || 'native',
    category: metadata.category || 'unknown',
    sensitive: metadata.sensitive || false,
    tags: metadata.tags || [],
    action,
    thread: get_thread_name(),
    threadId: Process.getCurrentThreadId(),
    processId: Process.id,
    context: {
      module: context.module || null,
      symbol: context.symbol || null,
      address: context.address || null,
      stack: context.stack || null
    },
    arguments: args,
    error,
    suspicious
  });

  globalThis.sendEvent = ev => {
    if (!ev.hook) {
      console.error(`[sendEvent] Missing hook field in event: ${JSON.stringify(ev, null, 2)}`);
    }
    try { send(ev); }
    catch (e) { console.error(`[sendEvent] failed: ${e}`); }
  };

  // ───── Logging Utilities ────────────────────────────
  globalThis.readBytesSafe = (ptr, len) => {
    try { return (!ptr || ptr.isNull() || len <= 0) ? null : Memory.readByteArray(ptr, len); }
    catch { return null; }
  };

  globalThis.fridaSHA1 = bytes => {
    try { return Crypto.digest('sha1', bytes, { encoding: 'hex' }); }
    catch { return '<sha1-failed>'; }
  };

  globalThis.get_thread_name = () => {
    if (!isJavaAvailable()) return 'native-thread';
    try {
      return Java.use('java.lang.Thread').currentThread().getName();
    } catch {
      return 'unknown-thread';
    }
  };

  globalThis.get_java_stack = () => {
    if (!isJavaAvailable()) return null;
    try {
      return Java.use('java.lang.Exception').$new().getStackTrace()
        .map(f => f?.toString?.() || '<frame>').join('\n');
    } catch {
      return null;
    }
  };

  // ───── Hooking Utilities ────────────────────────────
  globalThis.safeAttach = (fn, callbacks, moduleName = null, opts = {}) => {
    const {
      initialDelay = 0,
      maxRetries = 10,
      retryInterval = 200,
      verbose = true
    } = opts;

    if (typeof fn !== 'string') {
      console.warn(`[safeAttach] Skipping non-string function name: ${String(fn)}`);
      return Promise.resolve(null);
    }

    const resolvedHooks = globalThis._resolvedHooks || new Set();
    globalThis._resolvedHooks = resolvedHooks;

    return new Promise((resolve, reject) => {
      let attempts = 0;
      const key = `${moduleName || '?'}:${fn}`;

      const tryHook = () => {
        if (resolvedHooks.has(key)) {
          verbose && console.log(`[safeAttach] Skipping duplicate hook: ${fn}`);
          return resolve(null);
        }

        let addr = null;
        try {
          addr = tryResolve(fn, moduleName, verbose);
          if (!addr || !(addr instanceof NativePointer) || addr.isNull()) {
            return retry(`[safeAttach] Invalid address for ${fn}`);
          }
        } catch (e) {
          return retry(`[safeAttach] Failed to resolve ${fn}: ${e.message}`);
        }

        try {
          Interceptor.attach(addr, callbacks);
          resolvedHooks.add(key);
          verbose && console.log(`[safeAttach] Hooked ${fn} at ${addr}`);
          resolve(addr);
        } catch (e) {
          retry(`[safeAttach] attach failed for ${fn}: ${e.message}`);
        }
      };

      const retry = msg => {
        if (++attempts < maxRetries) {
          verbose && console.warn(`${msg}, retry #${attempts}`);
          setTimeout(tryHook, Math.min(retryInterval * Math.pow(1.5, attempts), 3000));
        } else {
          console.error(`GAVE UP on ${fn}`);
          reject(`GAVE UP on ${fn}`);
        }
      };

      setTimeout(tryHook, initialDelay);
    });
  };

  function tryResolve(fn, mod, verbose) {
    if (typeof fn !== 'string') return null;

    const altNames = [
      fn, `__${fn}`, `${fn}_64`, `${fn}64`, `${fn}_2`, `_${fn}`
    ];

    const tryNames = (resolverFn, label) => {
      for (const name of altNames) {
        try {
          const addr = resolverFn(name);
          if (addr) {
            verbose && console.log(`[safeAttach] Resolved ${name} via ${label}`);
            return addr;
          }
        } catch (_) {}
      }
      return null;
    };

    // Exported symbols
    if (mod) {
      const addr = tryNames(name => Module.findExportByName(mod, name), `Module(${mod}).exports`);
      if (addr) return addr;
    }

    for (const lib of fallbackLibs) {
      const addr = tryNames(name => Module.findExportByName(lib, name), `exports in ${lib}`);
      if (addr) return addr;
    }

    // Symbol table
    if (mod) {
      const addr = tryNames(name => Module.findSymbolByName(mod, name), `Module(${mod}).symbols`);
      if (addr) return addr;
    }

    for (const lib of fallbackLibs) {
      const addr = tryNames(name => Module.findSymbolByName(lib, name), `symbols in ${lib}`);
      if (addr) return addr;
    }

    // ApiResolver fallback
    try {
      const resolver = new ApiResolver("module");
      const results = resolver.enumerateMatches(`exports:*${fn}*`);
      if (results.length > 0) {
        const addr = results[0].address;
        verbose && console.log(`[safeAttach] Resolved ${fn} via ApiResolver at ${addr}`);
        return addr;
      }
    } catch (e) {
      verbose && console.warn(`[safeAttach] ApiResolver error: ${e.message}`);
    }

    // Brute-force last resort
    for (const m of Process.enumerateModules()) {
      for (const exp of m.enumerateExports()) {
        if (altNames.includes(exp.name)) {
          verbose && console.log(`[safeAttach] Brute-forced ${exp.name} in ${m.name}`);
          return exp.address;
        }
      }
    }

    return null;
  }

  // ───── JVM Ready Signal ─────────────────────────────
  runWhenJavaIsReady({
    retryInterval: 500,
    maxRetries: 60,
    verbose: true
  }).then(() => {
    send({ type: 'jvm_ready' });
    console.log('[frida_helpers] JVM ready signal sent');
  }).catch(err => {
    console.error('[frida_helpers] JVM never became available:', err);
  });

})();
