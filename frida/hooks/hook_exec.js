'use strict';

(async function () {
  const metadata = {
    name: "hook_exec",
    description: "Hooks native exec() calls",
    category: "native_injection",
    tags: ["native", "exec", "process"],
    sensitive: true,
    entrypoint: "native"
  };

  const execFunctions = [
    { name: "execve", args: [0, 1], module: "libc.so" },
    { name: "system", args: [0], module: "libc.so" },
    { name: "popen", args: [0], module: "libc.so" }
  ];

  const tryReadCString = (ptr) => {
    try {
      return ptr.readCString();
    } catch (_) {
      return "<unreadable>";
    }
  };

  const get_native_stack = (ctx) => {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`)
        .join("\n");
    } catch (_) {
      return "N/A";
    }
  };

  try {
    const log = await waitForLogger(metadata);

    for (const fn of execFunctions) {
      // Destructure values to avoid closure issues
      const { name: fnName, args: argIndices, module } = fn;

      try {
        await safeAttach(fnName, {
          onEnter(args) {
            const argMap = {};
            argIndices.forEach(i => {
              argMap[`arg${i}`] = tryReadCString(args[i]);
            });

            const evt = buildEvent({
              metadata,
              action: fnName,
              context: {
                module,
                stack: get_native_stack(this.context)
              },
              args: argMap
            });

            log(evt);
            console.log(`[hook_exec] ${fnName} called:`, JSON.stringify(argMap));
          }
        }, module, {
          maxRetries: 10,
          retryInterval: 300,
          verbose: true
        });

        console.log(`[hook_exec] Hooked ${fnName}`);
      } catch (err) {
        console.error(`[hook_exec] Failed to attach ${fnName}: ${err}`);
      }
    }

    log(buildEvent({ metadata, action: "hook_loaded" }));
    send({ type: 'hook_loaded', hook: metadata.name });
    console.log(`[+] ${metadata.name} initialized`);

  } catch (e) {
    console.error(`[hook_exec] Logger setup failed: ${e}`);
  }
})();
