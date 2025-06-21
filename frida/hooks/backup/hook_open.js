'use strict';

(async function () {
  const metadata = {
    name: "hook_open",
    category: "filesystem",
    description: "Hooks native file open operations (including open64, creat, openat2)",
    tags: ["native", "file", "fs"],
    sensitive: true,
    entrypoint: "native"
  };

  const log = createHookLogger(metadata);

  function readSafeUtf8(ptr) {
    try { return ptr.readUtf8String(); }
    catch { return "<unreadable>"; }
  }

  function getBacktrace(ctx) {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .slice(0, 10)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`);
    } catch {
      return ["<no backtrace>"];
    }
  }

  const hookedFunctions = [
    "open", "open64", "openat", "openat2", "creat", "creat64"
  ];

  for (const fn of hookedFunctions) {
    try {
      await safeAttach(fn, {
        onEnter(args) {
          this.fn = fn;
          const argIndex = (fn === "openat" || fn === "openat2") ? 1 : 0;
          this.path = readSafeUtf8(args[argIndex]);
          this.ctx = this.context;
        },
        onLeave(retval) {
          const fd = retval?.toInt32?.() ?? -1;
          const isBad = /tmp|proc|dev|\.su|\.sh|\.exe/i.test(this.path);
          const ev = buildEvent({
            metadata,
            action: "file_open",
            source: "native",
            context: { stack: getBacktrace(this.ctx) },
            args: {
              function: this.fn,
              path: this.path,
              fd,
              error: fd < 0
            },
            suspicious: isBad,
            error: fd < 0
          });
          log(ev);
          console.log(`[hook_open] ${this.fn}("${this.path}") → FD=${fd}`);
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

  log(buildEvent({ metadata, action: "hook_loaded", args: {} }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized`);
})();
