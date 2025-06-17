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

  try {
    const log = await waitForLogger(metadata);

    for (const fn of execFunctions) {
      try {
        await safeAttach(fn.name, {
          onEnter(args) {
            try {
              const argMap = {};
              fn.args.forEach(i => {
                argMap[`arg${i}`] = tryReadCString(args[i]);
              });

              log({
                action: fn.name,
                args: argMap,
                module: fn.module,
                thread: get_thread_name(),
                stack: get_java_stack(),
                tags: ["native", "exec_call"]
              });

              console.log(`[hook_exec] ${fn.name} called:`, JSON.stringify(argMap));
            } catch (err) {
              console.error(`[hook_exec] Logging failed for ${fn.name}: ${err}`);
            }
          }
        }, fn.module, {
          maxRetries: 10,
          retryInterval: 300,
          verbose: true
        });

        console.log(`[hook_exec] Hooked ${fn.name}`);
      } catch (err) {
        console.error(`[hook_exec] Failed to attach ${fn.name}: ${err}`);
      }
    }

    send({ type: 'hook_loaded', hook: metadata.name, java: false });
    console.log(`[+] ${metadata.name} initialized`);

  } catch (e) {
    console.error(`[hook_exec] Logger setup failed: ${e}`);
  }
})();
