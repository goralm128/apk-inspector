'use strict';

maybeRunJavaHook(async () => {
  const metadata = {
    name: "hook_anti_analysis",
    category: "evasion",
    description: "Bypasses anti-debugging and anti-Frida checks (Java & native)",
    tags: ["native", "java", "frida", "debug", "evasion"],
    sensitive: true,
    entrypoint: "native"
  };

  const log = await waitForLogger(metadata);

  function getBacktrace(ctx) {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`);
    } catch (_) {
      return ["<no backtrace>"];
    }
  }

  function hookNativeAntiAnalysis() {
    const fns = [
      {
        name: "ptrace",
        type: "replace",
        cb: () => new NativeCallback(() => {
          log(buildEvent({
            metadata,
            action: "bypass_ptrace",
            args: {},
            suspicious: true
          }));
          return 0;
        }, 'int', ['int', 'int', 'pointer', 'int'])
      },
      {
        name: "exit",
        type: "attach",
        onEnter: function (args) {
          log(buildEvent({
            metadata,
            action: "bypass_exit",
            args: { code: args[0]?.toInt32?.() ?? -1 },
            context: { stack: getBacktrace(this.context) },
            suspicious: true
          }));
          args[0] = ptr(0);
        }
      },
      {
        name: "abort",
        type: "attach",
        onEnter: function () {
          log(buildEvent({
            metadata,
            action: "bypass_abort",
            context: { stack: getBacktrace(this.context) },
            suspicious: true
          }));
        }
      },
      {
        name: "kill",
        type: "attach",
        onEnter: function (args) {
          log(buildEvent({
            metadata,
            action: "bypass_kill",
            args: {
              pid: args[0]?.toInt32?.() ?? -1,
              sig: args[1]?.toInt32?.() ?? -1
            },
            context: { stack: getBacktrace(this.context) },
            suspicious: true
          }));
          args[1] = ptr(0); // Neutralize signal
        }
      }
    ];

    for (const fn of fns) {
      const addr = Module.findExportByName(null, fn.name);
      if (!addr) {
        console.warn(`[${metadata.name}] ${fn.name} not found`);
        continue;
      }

      try {
        if (fn.type === "replace") {
          Interceptor.replace(addr, fn.cb());
          console.log(`[${metadata.name}] Replaced ${fn.name}`);
        } else {
          Interceptor.attach(addr, { onEnter: fn.onEnter });
          console.log(`[${metadata.name}] Attached to ${fn.name}`);
        }
      } catch (e) {
        console.error(`[${metadata.name}] Error hooking ${fn.name}: ${e}`);
      }
    }
  }

  // Java hooks
  try {
    const Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function () {
      log(buildEvent({
        metadata,
        action: "bypass_debugger_check",
        suspicious: true
      }));
      return false;
    };

    const StringCls = Java.use("java.lang.String");
    StringCls.contains.implementation = function (sub) {
      const lower = sub?.toString?.().toLowerCase?.() ?? "";
      if (lower.includes("frida")) {
        log(buildEvent({
          metadata,
          action: "bypass_frida_string_check",
          args: { sub: lower },
          suspicious: true
        }));
        return false;
      }
      return this.contains(sub);
    };

    const System = Java.use("java.lang.System");
    System.exit.implementation = function (code) {
      log(buildEvent({
        metadata,
        action: "bypass_System_exit",
        args: { code },
        suspicious: true
      }));
    };

    const Runtime = Java.use("java.lang.Runtime");
    Runtime.exit.implementation = function (code) {
      log(buildEvent({
        metadata,
        action: "bypass_Runtime_exit",
        args: { code },
        suspicious: true
      }));
    };

    console.log(`[${metadata.name}] Java anti-analysis hooks installed`);
  } catch (e) {
    console.error(`[${metadata.name}] Java hook error: ${e}`);
  }

  // Native hooks
  try {
    hookNativeAntiAnalysis();
    log(buildEvent({ metadata, action: "hook_loaded" }));
    send({ type: 'hook_loaded', hook: metadata.name });
    console.log(`[+] ${metadata.name} initialized`);
  } catch (e) {
    console.error(`[${metadata.name}] Native init failed: ${e}`);
  }
}, {
  name: "hook_anti_analysis",
  entrypoint: "java"
});
