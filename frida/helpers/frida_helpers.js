'use strict';

(function () {
  const fallbackLibs = ['libc.so', 'libdl.so', 'libc.so.6', 'libbionic.so', 'libc_malloc_debug.so'];
  const resolvedHooks = new Set();

  // ───── Java VM Utilities ───────────────────────────
  globalThis.isJavaAvailable = () => {
    try {
      return typeof Java !== 'undefined' && Java.available;
    } catch {
      return false;
    }
  };

  globalThis.runWhenJavaIsReady = ({
    retryInterval = 100,
    maxRetries = 2,
    verbose = true
  } = {}) => {
    if (globalThis._javaReadyPromise) return globalThis._javaReadyPromise;

    globalThis._javaReadyPromise = new Promise((resolve, reject) => {
      let attempts = 0;
      const attempt = () => {
        if (!isJavaAvailable()) return retry('[JavaCheck] Java not yet available');
        try {
          Java.perform(() => {
            verbose && console.log('[JavaCheck] Java.perform() OK');
            resolve();
          });
        } catch (e) {
          retry(`[JavaCheck] perform error: ${e}`);
        }
      };

      const retry = (msg) => {
        if (++attempts <= maxRetries) {
          verbose && console.warn(`${msg}, retry #${attempts}`);
          setTimeout(attempt, retryInterval * Math.pow(1.5, attempts));
        } else {
          const errMsg = '[JavaCheck] timed out';
          verbose && console.error(errMsg);
          reject(errMsg);
        }
      };

      attempt();
    });

    return globalThis._javaReadyPromise;
  };

  globalThis.maybeRunJavaHook = (cb, metadata = {}) => {
    return metadata.entrypoint?.toLowerCase() === 'java'
      ? runWhenJavaIsReady().then(cb).catch(console.error)
      : cb();
  };

  globalThis.ifJava = fn => isJavaAvailable() ? fn() : undefined;

  // ───── Event Builder and Logger ────────────────────
  globalThis.buildEvent = ({
    metadata = {},
    action = null,
    context = {},
    args = {},
    tags = [],
    error = false,
    suspicious = false
  } = {}) => ({
    timestamp: new Date().toISOString(),
    hook: metadata.name || 'unknown',
    entrypoint: metadata.entrypoint || 'native',
    category: metadata.category || 'uncategorized',
    sensitive: metadata.sensitive ?? false,
    tags,
    action,
    thread: getThreadName(),
    threadId: Process.getCurrentThreadId(),
    processId: Process.id,
    context: { ...context, stack: context.stack ?? null },
    arguments: args,
    error,
    suspicious
  });

  globalThis.createHookLogger = metadata => event => {
    event.hook = event.hook || metadata.name || 'unknown';
    event.entrypoint = event.entrypoint || metadata.entrypoint || 'native';
    event.timestamp = event.timestamp || new Date().toISOString();
    event.tags = Array.from(new Set([...(metadata.tags || []), ...(event.tags || [])]));
    event.sensitive = metadata.sensitive ?? false;
    send(event);
  };

  globalThis.waitForLogger = async metadata => createHookLogger(metadata);
  globalThis.sendEvent = event => {
    try {
      send(event);
    } catch (e) {
      console.error('[sendEvent] failed', e);
    }
  };

  // ───── Utility Functions ───────────────────────────
  globalThis.readBytesSafe = (ptr, len) =>
    (!ptr || ptr.isNull() || len <= 0) ? null : Memory.readByteArray(ptr, len);

  globalThis.fridaSHA1 = bytes => {
    try {
      return Crypto.digest('sha1', bytes, { encoding: 'hex' });
    } catch {
      return '<sha1-error>';
    }
  };

  function getThreadName() {
    if (!isJavaAvailable()) return 'native-thread';
    try {
      return Java.use('java.lang.Thread').currentThread().getName();
    } catch {
      return 'unknown-thread';
    }
  }

  globalThis.get_thread_name = getThreadName;

  globalThis.formatBacktrace = (ctx, limit = 10) => {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .slice(0, limit)
        .map(DebugSymbol.fromAddress)
        .map(s => `${s.moduleName || '?'}!${s.name || '?'}@${s.address}`);
    } catch {
      return ['<no-backtrace>'];
    }
  };

  // ───── Path Normalizer ─────────────────────────────
  globalThis.normalizePath = path => {
    try {
      if (path.includes('/proc/self/fd/')) {
        const fd = parseInt(path.split('/').pop(), 10);
        const real = File.readlink(`/proc/self/fd/${fd}`);
        return real || path;
      }
    } catch {}
    return path;
  };

  // ───── Safe Hooking Utility ────────────────────────
  globalThis.safeAttach = (fn, callbacks, moduleName = null, opts = {}) => {
    const {
      initialDelay = 0,
      maxRetries = 10,
      retryInterval = 200,
      verbose = true
    } = opts;

    return new Promise((resolve, reject) => {
      let tries = 0;
      const key = `${moduleName || '?'}:${fn}`;

      const attempt = () => {
        if (resolvedHooks.has(key)) {
          verbose && console.log(`${fn} already hooked`);
          return resolve(null);
        }

        let addr;
        try {
          addr = tryResolve(fn, moduleName, verbose);
          if (!addr || addr.isNull()) return retry('invalid address');
        } catch (e) {
          return retry(`resolve error: ${e}`);
        }

        try {
          Interceptor.attach(addr, callbacks);
          resolvedHooks.add(key);
          verbose && console.log(`Hooked ${fn} @ ${addr}`);
          resolve(addr);
        } catch (e) {
          retry(`attach error: ${e}`);
        }
      };

      const retry = (msg) => {
        if (++tries < maxRetries) {
          setTimeout(attempt, retryInterval * Math.pow(1.3, tries));
        } else {
          reject(`GAVE UP on ${fn}: ${msg}`);
        }
      };

      setTimeout(attempt, initialDelay);
    });
  };

  function tryResolve(fn, mod, verbose) {
    const variants = [fn, `__${fn}`, `${fn}64`, `${fn}_64`, `_${fn}`, `${fn}_2`];

    const tryFind = (resolver, label) => {
      for (const name of variants) {
        try {
          const addr = resolver(name);
          if (addr) {
            verbose && console.log(`Resolved ${name} via ${label}`);
            return addr;
          }
        } catch {}
      }
      return null;
    };

    if (mod) {
      let addr = tryFind(n => Module.findExportByName(mod, n), `exports(${mod})`);
      if (addr) return addr;
    }

    for (const lib of fallbackLibs) {
      const addr = tryFind(n => Module.findExportByName(lib, n), `exports(${lib})`);
      if (addr) return addr;
    }

    if (mod) {
      const addr = tryFind(n => Module.findSymbolByName(mod, n), `symbols(${mod})`);
      if (addr) return addr;
    }

    for (const lib of fallbackLibs) {
      const addr = tryFind(n => Module.findSymbolByName(lib, n), `symbols(${lib})`);
      if (addr) return addr;
    }

    try {
      const r = new ApiResolver('module');
      const results = r.enumerateMatches(`exports:*${fn}*`);
      if (results.length > 0) {
        verbose && console.log(`Resolved ${fn} via ApiResolver`);
        return results[0].address;
      }
    } catch (e) {
      verbose && console.warn('ApiResolver err', e);
    }

    for (const m of Process.enumerateModules()) {
      for (const exp of m.enumerateExports()) {
        if (variants.includes(exp.name)) {
          verbose && console.log(`Resolved ${exp.name} in ${m.name}`);
          return exp.address;
        }
      }
    }

    return null;
  }

  // ───── Notify Java Ready for Downstream Signals ────
  runWhenJavaIsReady({ retryInterval: 100, maxRetries: 2, verbose: true })
    .then(() => {
      send({ type: 'jvm_ready' });
      console.log('[frida_helpers] JVM ready');
    })
    .catch(err => console.error('[frida_helpers] JVM not ready:', err));
})();
