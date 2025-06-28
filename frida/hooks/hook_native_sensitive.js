'use strict';

/**
 * hook_native_sensitive.js
 *
 * Hooks critical native libc execution APIs like execve, system, fork, dlopen, etc.
 * Useful for detecting command execution, dynamic code loading, or sandbox evasion.
 */

(async function () {
  const metadata = {
    name: 'hook_native_sensitive',
    category: 'native_calls',
    description: 'Hooks sensitive native functions such as system, execve, dlopen, etc.',
    tags: ['native', 'libc', 'dangerous', 'execution'],
    sensitive: true,
    entrypoint: 'native'
  };

  const sensitiveFunctions = [
    'system', 'execve', 'popen', 'fork', 'vfork',
    'execl', 'execlp', 'execle', 'execv', 'execvp', 'execvpe',
    'dlopen'
  ];

  const safeReadCString = (ptr) => {
    try { return ptr.readCString(); }
    catch (_) { return '<unreadable>'; }
  };

  const formatBacktrace = (ctx) => {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .slice(0, 8)
        .map(sym => `${sym.moduleName || '?'}!${sym.name || '?'}@${sym.address}`);
    } catch (_) {
      return ['<no backtrace>'];
    }
  };

  const determineTags = (fnName, cmd) => {
    const tags = [fnName];
    const lowerCmd = (cmd || "").toLowerCase();
    if (lowerCmd.includes("su") || lowerCmd.includes("sh")) tags.push("proc_exec");
    if (lowerCmd.includes("frida") || lowerCmd.includes("debug")) tags.push("anti_analysis");
    if (fnName.startsWith("exec") || fnName === "system" || fnName === "popen") tags.push("exec_call");
    if (fnName === "dlopen") tags.push("dynamic_loading");
    if (["fork", "vfork"].includes(fnName)) tags.push("process_fork");
    return tags;
  };

  try {
    const log = await waitForLogger(metadata);
    console.log(`[${metadata.name}] Installing ${sensitiveFunctions.length} native hooks...`);

    const hookFunction = async (fnName) => {
      await safeAttach(fnName, {
        onEnter(args) {
          this.fnName = fnName;
          this.contextInfo = this.context;

          const caller = DebugSymbol.fromAddress(this.returnAddress) || {};
          const isExecLike = ['system', 'popen'].includes(fnName) || fnName.startsWith('exec');

          const command = isExecLike ? safeReadCString(args[0]) : (fnName === "dlopen" ? safeReadCString(args[0]) : null);
          const tags = determineTags(fnName, command);
          const suspicious = true;

          const event = buildEvent({
            metadata,
            action: fnName,
            context: {
              module: caller.moduleName || 'unknown',
              symbol: caller.name || 'unknown',
              address: this.contextInfo?.pc,
              stack: formatBacktrace(this.contextInfo)
            },
            args: {
              function: fnName,
              ...(command ? { command } : {})
            },
            suspicious,
            tags
          });

          log(event);
          console.log(`[${metadata.name}] ${fnName}${command ? `("${command}")` : "()"} ← ${caller.name || 'unknown'}`);
        }
      }, null, {
        maxRetries: 10,
        retryInterval: 250,
        verbose: true
      }).then(() => {
        console.log(`[${metadata.name}] Hooked ${fnName}`);
      }).catch(err => {
        console.error(`[${metadata.name}] Failed to hook ${fnName}: ${err}`);
      });
    };

    for (const fn of sensitiveFunctions) {
      await hookFunction(fn);
    }

    log(buildEvent({ metadata, action: 'hook_loaded' }));
    send({ type: 'hook_loaded', hook: metadata.name });
    console.log(`[+] ${metadata.name} initialized`);
  } catch (e) {
    console.error(`[${metadata.name}] Setup failed: ${e}`);
  }
})();
