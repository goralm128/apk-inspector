'use strict';

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
    'execl', 'execlp', 'execle', 'execv', 'execvp', 'execvpe', 'dlopen'
  ];

  const safeReadCString = (ptr) => {
    try {
      return ptr.readCString();
    } catch (_) {
      return '<unreadable>';
    }
  };

  const formatBacktrace = (ctx) => {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .map(sym => `${sym.moduleName || '?'}!${sym.name || '?'}@${sym.address}`);
    } catch (_) {
      return ['<no backtrace>'];
    }
  };

  try {
    const log = await waitForLogger(metadata);
    console.log(`[${metadata.name}] Installing ${sensitiveFunctions.length} native hooks...`);

    const hookFunction = async (fnName) => {
      await safeAttach(fnName, {
        onEnter(args) {
          const caller = DebugSymbol.fromAddress(this.returnAddress) || {};
          const mod = caller.moduleName || 'unknown';
          const sym = caller.name || 'unknown';

          const isExecLike = ['system', 'popen'].includes(fnName) || fnName.startsWith('exec');
          const cmd = isExecLike ? safeReadCString(args[0]) : null;

          const event = buildEvent({
            metadata,
            action: fnName,
            context: {
              module: mod,
              symbol: sym,
              address: this.context?.pc,
              stack: formatBacktrace(this.context)
            },
            args: {
              function: fnName,
              ...(cmd ? { command: cmd } : {})
            },
            suspicious: true
          });

          log(event);
          if (cmd) {
            console.log(`[${metadata.name}] ${fnName}("${cmd}") ← ${sym}`);
          } else {
            console.log(`[${metadata.name}] ${fnName}() ← ${sym}`);
          }
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

    log(buildEvent({ metadata, action: 'hook_loaded'}));
    send({ type: 'hook_loaded', hook: metadata.name });

    console.log(`[+] ${metadata.name} initialized`);
  } catch (e) {
    console.error(`[${metadata.name}] Setup failed: ${e}`);
  }
})();
