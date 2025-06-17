'use strict';

(async function () {
  const metadata = {
    name: "hook_native_sensitive",
    category: "native_calls",
    description: "Hooks sensitive native functions such as system, execve, dlopen, etc.",
    tags: ["native", "libc", "dangerous", "execution"],
    sensitive: true,
    entrypoint: "native" 
  };

  const sensitiveFunctions = [
    "system", "execve", "popen", "fork", "vfork",
    "execl", "execlp", "execle", "execv", "execvp", "execvpe", "dlopen"
  ];

  const safeReadCString = (ptr) => {
    try {
      return ptr.readCString();
    } catch (_) {
      return "<unreadable>";
    }
  };

  const getBacktrace = (context) => {
    try {
      return Thread.backtrace(context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`)
        .join("\n");
    } catch (_) {
      return "N/A";
    }
  };

  const waitForLoggerWithoutJava = (metadata, timeout = 5000, interval = 100) => {
    return new Promise((resolve, reject) => {
      const start = Date.now();
      const check = () => {
        if (typeof globalThis.createHookLogger === 'function') {
          const logger = createHookLogger(metadata);
          resolve(logger);
        } else if (Date.now() - start < timeout) {
          setTimeout(check, interval);
        } else {
          reject(new Error(`[${metadata.name}] Logger unavailable after ${timeout}ms`));
        }
      };
      check();
    });
  };

  try {
    const log = await waitForLoggerWithoutJava(metadata);
    console.log(`[${metadata.name}] Installing ${sensitiveFunctions.length} native hooks...`);

    for (const func of sensitiveFunctions) {
      await safeAttach(func, {
        onEnter(args) {
          try {
            const caller = DebugSymbol.fromAddress(this.returnAddress) || {};
            const moduleName = caller.moduleName || "unknown";
            const symbolName = caller.name || "unknown";
            const addr = this.context.pc;

            let cmd = "";
            if (["system", "popen"].includes(func) || func.startsWith("exec")) {
              cmd = safeReadCString(args[0]);
            }

            log({
              action: func,
              command: cmd,
              module: moduleName,
              symbol: symbolName,
              address: addr.toString(),
              thread: get_thread_name(),
              threadId: Process.getCurrentThreadId(),
              processId: Process.id,
              stack: getBacktrace(this.context),
              tags: ["native", "sensitive_call"]
            });

            console.log(`[${metadata.name}] ${func}("${cmd}")`);
          } catch (e) {
            console.error(`[${metadata.name}] Logging failed in ${func}:`, e);
          }
        }
      }, null, {
        maxRetries: 10,
        retryInterval: 250,
        verbose: true
      }).then(() => {
        console.log(`[${metadata.name}] Hooked ${func}`);
      }).catch(err => {
        console.error(`[${metadata.name}] Failed to hook ${func}: ${err}`);
      });
    }

    send({
      type: 'hook_loaded',
      hook: metadata.name,
      java: false
    });

    console.log(`[+] ${metadata.name} initialized`);
  } catch (e) {
    console.error(`[${metadata.name}] Logger setup failed: ${e}`);
  }
})();
