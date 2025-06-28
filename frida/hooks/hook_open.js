'use strict';

/**
 * hook_open.js
 *
 * Hooks native file opening functions to monitor access to suspicious paths or binaries.
 * Targets libc functions like open(), open64(), creat(), openat(), etc.
 */

(async function () {
  const metadata = {
    name: "hook_open",
    category: "filesystem",
    description: "Hooks native file open operations (including open64, creat, openat2)",
    tags: ["native", "file", "fs", "sensitive_path"],
    sensitive: true,
    entrypoint: "native"
  };

  const log = createHookLogger(metadata);

  const readSafeUtf8 = (ptr) => {
    try { return ptr.readUtf8String(); }
    catch (_) { return "<unreadable>"; }
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

  const isSensitivePath = (path) => {
    const lowered = path.toLowerCase();
    return lowered.includes("/dev/") || lowered.includes("/proc/") || 
           lowered.includes("/tmp/") || lowered.includes(".su") || 
           lowered.includes(".sh") || lowered.includes(".exe");
  };

  const hookedFunctions = [
    "open", "open64", "openat", "openat2", "creat", "creat64"
  ];

  for (const fn of hookedFunctions) {
    try {
      await safeAttach(fn, {
        onEnter(args) {
          this.fn = fn;
          const pathArgIndex = (fn === "openat" || fn === "openat2") ? 1 : 0;
          this.path = normalizePath(readSafeUtf8(args[pathArgIndex]));
          this.ctx = this.context;
        },
        onLeave(retval) {
          const fd = retval?.toInt32?.() ?? -1;
          const suspicious = isSensitivePath(this.path);
          const tags = ["file_open"];
          if (suspicious) tags.push("sensitive_path");

          const event = buildEvent({
            metadata,
            action: "file_open",
            context: {
              stack: formatBacktrace(this.ctx)
            },
            args: {
              function: this.fn,
              path: this.path,
              fd,
              error: fd < 0
            },
            suspicious,
            error: fd < 0,
            tags
          });

          log(event);
          console.log(`[hook_open] ${this.fn}("${this.path}") → FD=${fd} [suspicious=${suspicious}]`);
        }
      }, null, {
        maxRetries: 10,
        retryInterval: 300,
        verbose: true
      });

      console.log(`[hook_open] Hooked ${fn}`);
    } catch (err) {
      console.warn(`[hook_open] Failed to hook ${fn}: ${err}`);
    }
  }

  log(buildEvent({ metadata, action: "hook_loaded" }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized`);
})();
