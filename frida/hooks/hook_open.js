'use strict';

(async function () {
  const metadata = {
    name: "hook_open",
    category: "filesystem",
    description: "Hooks native file open operations",
    tags: ["native", "file", "fs", "fopen", "openat"],
    sensitive: true
  };

  const fileFunctions = [
    { name: "open", argIndex: 0 },
    { name: "openat", argIndex: 1 },
    { name: "fopen", argIndex: 0 }
  ];

  function readSafeUtf8(ptr) {
    try {
      return ptr.readUtf8String();
    } catch (_) {
      return "<unreadable>";
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
      fileFunctions.forEach(fn => {
        safeAttach(fn.name, {
          onEnter(args) {
            this.path = readSafeUtf8(args[fn.argIndex]);
            this.func = fn.name;
            this.context = this.context;
          },
          onLeave(retval) {
            const fd = retval?.toInt32?.() ?? -1;

            log({
              action: "file_open",
              function: this.func,
              path: this.path,
              fd,
              error: fd < 0,
              thread: get_thread_name(),
              threadId: Process.getCurrentThreadId(),
              processId: Process.id,
              stack: getBacktrace(this.context),
              tags: ["fs", "file_open"]
            });

            console.log(`[hook_open] ${this.func}("${this.path}") → FD=${fd}`);
          }
        }, null, {
          maxRetries: 8,
          retryInterval: 250,
          verbose: true
        }).then(() => {
          console.log(`[hook_open] Successfully hooked ${fn.name}`);
        }).catch(err => {
          console.error(`[hook_open] Failed to hook ${fn.name}: ${err}`);
        });
      });

      send({ type: 'hook_loaded', hook: metadata.name, java: false });
      console.log(`[+] ${metadata.name} initialized`);
    });

  } catch (e) {
    console.error(`[hook_open] Logger or setup failed: ${e}`);
  }
})();
