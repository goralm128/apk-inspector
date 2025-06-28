'use strict';

/**
 * hook_native_anubis_runtime.js
 *
 * Hooks native APIs used by Anubis and similar malware families.
 * Focuses on execution, memory, and network operations: execve, dlopen, send, mmap, etc.
 */

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

  const determineTags = (fn, preview) => {
    const tags = [fn];
    const lc = preview.toLowerCase();
    if (fn.startsWith("exec") || lc.includes("su") || lc.includes("sh")) tags.push("proc_exec");
    if (fn === "dlopen" && lc.includes("frida")) tags.push("anti_frida");
    if (["mmap", "mprotect"].includes(fn)) tags.push("memory_access");
    if (["send", "recv", "connect"].includes(fn)) tags.push("network_io");
    if (["strcmp", "strncmp", "memcmp"].includes(fn) && lc.includes("frida")) tags.push("frida_check");
    return tags;
  };

  const hookFunction = async (fnName) => {
    await safeAttach(fnName, {
      onEnter(args) {
        this.fnName = fnName;
        this.args = args;
        this.ctx = this.context;
        this.preview = '';

        try {
          switch (fnName) {
            case 'execve':
            case 'system':
            case 'popen':
              this.preview = safeReadCString(args[0]);
              break;
            case 'dlopen':
              this.preview = safeReadCString(args[0]);
              break;
            case 'send':
            case 'recv':
              this.preview = Memory.readUtf8String(args[1], MAX_PREVIEW_BYTES).replace(/\s+/g, ' ');
              break;
            case 'strcmp':
            case 'strncmp':
            case 'memcmp':
              this.preview = [
                safeReadCString(args[0]),
                safeReadCString(args[1])
              ].join(' ↔ ');
              break;
            case 'open':
              this.preview = safeReadCString(args[0]);
              break;
            default:
              this.preview = "<preview unavailable>";
          }
        } catch {
          this.preview = "<unreadable>";
        }
      },
      onLeave(retval) {
        const caller = DebugSymbol.fromAddress(this.returnAddress) || {};
        const tags = determineTags(this.fnName, this.preview);
        const suspicious = true;

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
          suspicious,
          tags
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
