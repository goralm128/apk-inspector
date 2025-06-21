'use strict';

(async function () {
  const metadata = {
    name: "hook_root_access",
    category: "filesystem",
    description: "Bypasses native root detection",
    tags: ["native", "root", "file", "evasion", "frida"],
    sensitive: true,
    entrypoint: "native"
  };

  const log = createHookLogger(metadata);

  function readSafeUtf8(ptr) {
    try { return ptr.readUtf8String(); }
    catch { return "<unreadable>"; }
  }

  function getBacktrace(ctx) {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .slice(0, 10)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`);
    } catch {
      return ["<no backtrace>"];
    }
  }

  const suspiciousPaths = /\/(su|magisk|busybox|superuser|xposed|zygote|rootcloak|data\/local\/tmp|proc\/self\/maps|proc\/version)/i;
  const suspiciousCommands = /\b(su|getprop|whoami|busybox|which|mount|id|sh)\b/i;

  const hookedFunctions = new Set([
    "open", "open64", "access", "fopen", "stat", "stat64", "system", "execve"
  ]);

  const modulesToScan = ["libc.so", "libc.so.6", "libdl.so", "libbionic.so"];

  for (const lib of modulesToScan) {
    for (const fn of hookedFunctions) {
      let addr = Module.findExportByName(lib, fn);
      let method = "export";
      if (!addr) {
        try {
          addr = Module.findSymbolByName(lib, fn);
          method = "symbol";
        } catch (e) {
          console.warn(`[hook_root_access] findSymbolByName error for ${fn}@${lib}: ${e}`);
        }
      }

      if (!addr || addr.isNull()) {
        console.warn(`[hook_root_access] could not resolve ${fn} in ${lib}`);
        continue;
      }

      try {
        await safeAttach(fn, {
          onEnter(args) {
            this.fn = fn;
            this.ctx = this.context;
            this.shouldBypass = false;
            this.original = null;

            switch (fn) {
              case "open":
              case "open64":
              case "access":
              case "fopen":
              case "stat":
              case "stat64":
                this.path = readSafeUtf8(args[0]);
                if (this.path && suspiciousPaths.test(this.path)) {
                  this.shouldBypass = true;
                  this.original = this.path;
                }
                break;

              case "system":
                this.cmd = readSafeUtf8(args[0]);
                if (this.cmd && suspiciousCommands.test(this.cmd)) {
                  this.shouldBypass = true;
                  this.original = this.cmd;
                }
                break;

              case "execve":
                this.execPath = readSafeUtf8(args[0]);
                this.execArgv = [];
                const argv = args[1];
                let i = 0;
                try {
                  while (!argv.add(i * Process.pointerSize).readPointer().isNull()) {
                    const s = readSafeUtf8(argv.add(i * Process.pointerSize).readPointer());
                    this.execArgv.push(s);
                    i++;
                  }
                } catch (e) {
                  this.execArgv.push("<parse error>");
                }
                const joined = [this.execPath, ...this.execArgv].join(" ");
                if (joined && suspiciousCommands.test(joined)) {
                  this.shouldBypass = true;
                  this.original = joined;
                }
                break;
            }
          },

          onLeave(retval) {
            if (!this.shouldBypass) return;

            const action = `bypass_${this.fn}`;
            const ev = buildEvent({
              metadata,
              action,
              context: { stack: getBacktrace(this.ctx) },
              args: {
                function: this.fn,
                input: this.original,
                originalReturn: retval.toInt32?.() ?? null
              },
              suspicious: true,
              error: false
            });

            log(ev);

            if (this.fn === "fopen") {
              retval.replace(ptr(0));
            } else {
              retval.replace(ptr(-1));
            }

            console.log(`[hook_root_access] Bypassed ${this.fn}("${this.original}") → faked fail`);
          }
        }, lib, {
          maxRetries: 8,
          retryInterval: 250,
          verbose: true
        });

        console.log(`[hook_root_access] hooked ${fn} from ${lib} via ${method}`);
      } catch (err) {
        console.warn(`[hook_root_access] Failed to hook ${fn} in ${lib}: ${err}`);
      }
    }
  }

  log(buildEvent({ metadata, action: "hook_loaded", args: {} }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log("[+] hook_root_access initialized");
})();
