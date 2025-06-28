'use strict';

/**
 * hook_root_access.js
 *
 * Detects and bypasses native root detection techniques using file, exec, and system calls.
 * Intercepts access to sensitive paths and commands linked to root status.
 */

(async function () {
  const metadata = {
    name: "hook_root_access",
    category: "filesystem",
    description: "Bypasses native root detection via file and command interception",
    tags: ["native", "root", "file", "evasion", "frida"],
    sensitive: true,
    entrypoint: "native"
  };

  const log = createHookLogger(metadata);

  const readSafeUtf8 = ptr => {
    try { return ptr.readUtf8String(); }
    catch (_) { return "<unreadable>"; }
  };

  const getBacktrace = ctx => {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .slice(0, 10)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`);
    } catch (_) {
      return ["<no backtrace>"];
    }
  };

  const suspiciousPaths = /\/(su|magisk|busybox|superuser|xposed|zygote|rootcloak|data\/local\/tmp|proc\/self\/maps|proc\/version)/i;
  const suspiciousCommands = /\b(su|getprop|whoami|busybox|which|mount|id|sh)\b/i;

  const hookedFunctions = [
    "open", "open64", "access", "fopen", "stat", "stat64", "system", "execve"
  ];

  const targetModules = ["libc.so", "libc.so.6", "libdl.so", "libbionic.so"];

  for (const module of targetModules) {
    for (const fnName of hookedFunctions) {
      let addr = Module.findExportByName(module, fnName) || Module.findSymbolByName(module, fnName);
      if (!addr || addr.isNull()) {
        console.warn(`[hook_root_access] ❌ Could not resolve ${fnName} in ${module}`);
        continue;
      }

      try {
        await safeAttach(fnName, {
          onEnter(args) {
            this.fn = fnName;
            this.ctx = this.context;
            this.shouldBypass = false;
            this.original = null;

            try {
              switch (fnName) {
                case "open":
                case "open64":
                case "access":
                case "fopen":
                case "stat":
                case "stat64":
                  const path = normalizePath(readSafeUtf8(args[0]));
                  if (suspiciousPaths.test(path)) {
                    this.shouldBypass = true;
                    this.original = path;
                  }
                  break;

                case "system":
                  const cmd = readSafeUtf8(args[0]);
                  if (suspiciousCommands.test(cmd)) {
                    this.shouldBypass = true;
                    this.original = cmd;
                  }
                  break;

                case "execve":
                  const bin = readSafeUtf8(args[0]);
                  const argv = args[1];
                  const parts = [bin];
                  let i = 0;
                  try {
                    while (!argv.add(i * Process.pointerSize).readPointer().isNull()) {
                      parts.push(readSafeUtf8(argv.add(i * Process.pointerSize).readPointer()));
                      i++;
                    }
                  } catch (_) {
                    parts.push("<parse_error>");
                  }
                  const fullCmd = parts.join(" ");
                  if (suspiciousCommands.test(fullCmd)) {
                    this.shouldBypass = true;
                    this.original = fullCmd;
                  }
                  break;
              }
            } catch (_) {
              console.warn(`[hook_root_access] parse error in ${fnName}`);
            }
          },

          onLeave(retval) {
            if (!this.shouldBypass) return;

            log(buildEvent({
              metadata,
              action: `bypass_${this.fn}`,
              context: { stack: getBacktrace(this.ctx) },
              args: {
                function: this.fn,
                input: this.original,
                originalReturn: retval.toInt32?.() ?? null
              },
              suspicious: true
            }));

            if (this.fn === "fopen") retval.replace(ptr(0));
            else retval.replace(ptr(-1));

            console.log(`[hook_root_access] ⚠️ Bypassed ${this.fn}("${this.original}") → fake fail`);
          }
        }, module, {
          maxRetries: 8,
          retryInterval: 250,
          verbose: true
        });

        console.log(`[hook_root_access] ✅ Hooked ${fnName} in ${module}`);
      } catch (err) {
        console.error(`[hook_root_access] Error hooking ${fnName} in ${module}: ${err}`);
      }
    }
  }

  log(buildEvent({ metadata, action: "hook_loaded" }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log("[+] hook_root_access initialized");
})();
