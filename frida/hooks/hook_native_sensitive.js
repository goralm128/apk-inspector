'use strict';

(async function () {
  const metadata = {
    name: "hook_native_sensitive",
    description: "Monitors native calls to ptrace, getenv, fgets, kill for anti-debug and evasion tactics",
    category: "native_sensitive",
    tags: ["native", "anti_debug", "env_check", "sensitive_read"],
    sensitive: true
  };

  function tryReadCString(ptr) {
    try {
      return ptr.readCString();
    } catch (_) {
      return "<unreadable>";
    }
  }

  function formatBacktrace(ctx) {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"} @ ${sym.address}`);
    } catch (_) {
      return ["<no backtrace>"];
    }
  }

  try {
    const log = await waitForLogger(metadata);

    runWhenJavaIsReady(() => {
      const hooks = [
        {
          name: "ptrace",
          module: "libc.so",
          onEnter(args) {
            this.request = args[0]?.toInt32?.();
            this.pid = args[1]?.toInt32?.();
          },
          onLeave() {
            log({
              action: "ptrace",
              request: this.request,
              pid: this.pid,
              anti_debug: true,
              tags: ["anti_debug"],
              thread: get_thread_name(),
              threadId: Process.getCurrentThreadId(),
              processId: Process.id,
              stack: formatBacktrace(this.context)
            });
          }
        },
        {
          name: "getenv",
          module: "libc.so",
          onEnter(args) {
            this.key = tryReadCString(args[0]);
          },
          onLeave(retval) {
            log({
              action: "getenv",
              key: this.key,
              value: retval.isNull() ? "<null>" : tryReadCString(retval),
              env_check: true,
              tags: ["env_check"],
              thread: get_thread_name(),
              threadId: Process.getCurrentThreadId(),
              processId: Process.id,
              stack: formatBacktrace(this.context)
            });
          }
        },
        {
          name: "fgets",
          module: "libc.so",
          onEnter(args) {
            this.buf = args[0];
          },
          onLeave() {
            try {
              const content = tryReadCString(this.buf);
              log({
                action: "fgets",
                content,
                sensitive_read: true,
                tags: ["sensitive_read"],
                thread: get_thread_name(),
                threadId: Process.getCurrentThreadId(),
                processId: Process.id,
                stack: formatBacktrace(this.context)
              });
            } catch (_) {
              // Ignore unreadable memory
            }
          }
        },
        {
          name: "kill",
          module: "libc.so",
          onEnter(args) {
            this.pid = args[0]?.toInt32?.();
            this.sig = args[1]?.toInt32?.();
          },
          onLeave() {
            const suspicious = this.sig === 9 || this.sig === 11;
            log({
              action: "kill",
              pid: this.pid,
              signal: this.sig,
              anti_debug: suspicious,
              tags: suspicious ? ["anti_debug"] : ["kill"],
              thread: get_thread_name(),
              threadId: Process.getCurrentThreadId(),
              processId: Process.id,
              stack: formatBacktrace(this.context)
            });
          }
        }
      ];

      for (const { name, module, onEnter, onLeave } of hooks) {
        safeAttach(name, { onEnter, onLeave }, module, {
          maxRetries: 8,
          retryInterval: 250,
          verbose: true
        }).then(() => {
          console.log(`[hook_native_sensitive] Hooked ${name}`);
        }).catch(err => {
          console.error(`[hook_native_sensitive] Failed to hook ${name}: ${err}`);
        });
      }

      send({ type: 'hook_loaded', hook: metadata.name, java: false });
      console.log(`[+] ${metadata.name} initialized`);
    });

  } catch (e) {
    console.error(`[hook_native_sensitive] Logger setup failed: ${e}`);
  }
})();
