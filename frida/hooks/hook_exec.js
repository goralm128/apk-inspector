'use strict';

(async function () {
  const metadata = {
    name: "hook_exec",
    description: "Hooks native exec() calls with suspicion tagging",
    category: "native_injection",
    tags: ["native", "exec", "process", "suspicious"],
    sensitive: true,
    entrypoint: "native"
  };

  const execFunctions = [
    { name: "execve", args: [0, 1], module: "libc.so" },
    { name: "system", args: [0], module: "libc.so" },
    { name: "popen", args: [0], module: "libc.so" }
  ];

  const tryReadCString = (ptr) => {
    try { return ptr.readCString(); }
    catch (_) { return "<unreadable>"; }
  };

  const get_native_stack = (ctx) => {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`);
    } catch (_) {
      return ["<no backtrace>"];
    }
  };

  const isSuspiciousCmd = (cmd) => {
    const lowered = cmd.toLowerCase();
    return lowered.includes("su") || lowered.includes("sh") || lowered.includes("/data/local") ||
           lowered.includes("/tmp") || lowered.includes("frida") || lowered.includes("debug");
  };

  try {
    const log = await waitForLogger(metadata);

    for (const fn of execFunctions) {
      const { name: fnName, args: argIndices, module } = fn;

      await safeAttach(fnName, {
        onEnter(args) {
          const argMap = {};
          argIndices.forEach(i => {
            argMap[`arg${i}`] = tryReadCString(args[i]);
          });

          const cmdStr = argMap.arg0 || "";
          const suspicious = isSuspiciousCmd(cmdStr);
          const tags = ["exec_call"];
          if (suspicious) tags.push("suspicious_exec");
          if (cmdStr.includes("su")) tags.push("su_command");
          if (cmdStr.includes("frida")) tags.push("frida_target");

          log(buildEvent({
            metadata,
            action: fnName,
            context: {
              module,
              stack: get_native_stack(this.context)
            },
            args: argMap,
            suspicious,
            tags
          }));

          console.log(`[hook_exec] ${fnName}("${cmdStr}") [suspicious=${suspicious}]`);
        }
      }, module, {
        maxRetries: 10,
        retryInterval: 300,
        verbose: true
      });

      console.log(`[hook_exec] Hooked ${fnName}`);
    }

    log(buildEvent({ metadata, action: "hook_loaded" }));
    send({ type: 'hook_loaded', hook: metadata.name });
    console.log(`[+] ${metadata.name} initialized`);

  } catch (e) {
    console.error(`[hook_exec] Logger setup failed: ${e}`);
  }
})();
