'use strict';

(async function () {
  const metadata = {
    name: 'hook_native_anubis_runtime',
    category: 'native_calls',
    description: 'Hooks native-level APIs relevant to Pandemidestek/Anubis malware (exec, dlopen, mmap, send, mprotect, etc)',
    tags: ['native', 'execution', 'network', 'memory', 'dex', 'anubis'],
    sensitive: true,
    entrypoint: 'native'
  };

  const targetFunctions = [
    'execve', 'system', 'popen', 'dlopen',
    'send', 'recv', 'connect',
    'mprotect', 'mmap', 'open',
    'strcmp', 'strncmp', 'memcmp'
  ];

  const log = await waitForLogger(metadata);

  const MAX_PREVIEW_BYTES = 100;

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

  const hookFunction = async (fnName) => {
    await safeAttach(fnName, {
      onEnter(args) {
        this.fnName = fnName;
        this.args = args;
        this.ctx = this.context;
        this.preview = '';

        if (['execve', 'system', 'popen'].includes(fnName)) {
          this.preview = safeReadCString(args[0]);
        } else if (['send', 'recv'].includes(fnName)) {
          try {
            const preview = Memory.readUtf8String(args[1], MAX_PREVIEW_BYTES);
            this.preview = preview.replace(/\s+/g, ' ');
          } catch {
            this.preview = '<unreadable>';
          }
        } else if (fnName === 'dlopen') {
          this.preview = safeReadCString(args[0]);
        } else if (['strcmp', 'strncmp', 'memcmp'].includes(fnName)) {
          this.preview = [safeReadCString(args[0]), safeReadCString(args[1])].join(' ↔ ');
        }
      },
      onLeave(retval) {
        const caller = DebugSymbol.fromAddress(this.returnAddress) || {};
        const event = buildEvent({
          metadata,
          action: this.fnName,
          context: {
            module: caller.moduleName || 'unknown',
            symbol: caller.name || 'unknown',
            address: this.ctx?.pc,
            stack: formatBacktrace(this.ctx)
          },
          args: {
            function: this.fnName,
            preview: this.preview
          },
          suspicious: true
        });

        log(event);
        console.log(`[${metadata.name}] ${this.fnName}("${this.preview}") ← ${caller.name || 'unknown'}`);
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

  console.log(`[${metadata.name}] Installing ${targetFunctions.length} native hooks...`);
  for (const fn of targetFunctions) {
    await hookFunction(fn);
  }

  log(buildEvent({ metadata, action: 'hook_loaded' }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized`);
})();
