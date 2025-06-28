'use strict';

/**
 * hook_anti_analysis.js
 *
 * Bypasses anti-debugging, anti-Frida, and forced exit behaviors in Android apps (Java + native).
 * Hooks ptrace, kill, exit, abort (native) and common evasion tactics in Java classes.
 */

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

  const getBacktrace = (ctx) => {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`);
    } catch (_) {
      return ["<no backtrace>"];
    }
  };

  const hookNativeAntiAnalysis = () => {
    const nativeHooks = [
      {
        name: "ptrace",
        type: "replace",
        callback: () => new NativeCallback(() => {
          log(buildEvent({
            metadata,
            action: "bypass_ptrace",
            args: {},
            suspicious: true,
            tags: ["anti_debug"]
          }));
          return 0;
        }, 'int', ['int', 'int', 'pointer', 'int'])
      },
      {
        name: "exit",
        type: "attach",
        onEnter(args) {
          const code = args[0]?.toInt32?.() ?? -1;
          log(buildEvent({
            metadata,
            action: "bypass_exit",
            args: { code },
            context: { stack: getBacktrace(this.context) },
            suspicious: true,
            tags: ["forced_exit"]
          }));
          args[0] = ptr(0);
        }
      },
      {
        name: "abort",
        type: "attach",
        onEnter() {
          log(buildEvent({
            metadata,
            action: "bypass_abort",
            context: { stack: getBacktrace(this.context) },
            suspicious: true,
            tags: ["forced_abort"]
          }));
        }
      },
      {
        name: "kill",
        type: "attach",
        onEnter(args) {
          const pid = args[0]?.toInt32?.() ?? -1;
          const sig = args[1]?.toInt32?.() ?? -1;
          log(buildEvent({
            metadata,
            action: "bypass_kill",
            args: { pid, sig },
            context: { stack: getBacktrace(this.context) },
            suspicious: true,
            tags: ["anti_debug"]
          }));
          args[1] = ptr(0); // Neutralize signal
        }
      }
    ];

    for (const hook of nativeHooks) {
      const addr = Module.findExportByName(null, hook.name);
      if (!addr) {
        console.warn(`[${metadata.name}] ${hook.name} not found`);
        continue;
      }

      try {
        if (hook.type === "replace") {
          Interceptor.replace(addr, hook.callback());
          console.log(`[${metadata.name}] Replaced ${hook.name}`);
        } else {
          Interceptor.attach(addr, { onEnter: hook.onEnter });
          console.log(`[${metadata.name}] Attached to ${hook.name}`);
        }
      } catch (e) {
        console.error(`[${metadata.name}] Failed to hook ${hook.name}: ${e}`);
      }
    }
  };

  const hookJavaAntiAnalysis = () => {
    try {
      const Debug = Java.use("android.os.Debug");
      Debug.isDebuggerConnected.implementation = function () {
        log(buildEvent({
          metadata,
          action: "bypass_debugger_check",
          suspicious: true,
          tags: ["anti_debug"]
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
            suspicious: true,
            tags: ["anti_frida"]
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
          suspicious: true,
          tags: ["forced_exit"]
        }));
      };

      const Runtime = Java.use("java.lang.Runtime");
      Runtime.exit.implementation = function (code) {
        log(buildEvent({
          metadata,
          action: "bypass_Runtime_exit",
          args: { code },
          suspicious: true,
          tags: ["forced_exit"]
        }));
      };

      console.log(`[${metadata.name}] Java anti-analysis hooks installed`);
    } catch (e) {
      console.error(`[${metadata.name}] Java hook error: ${e}`);
    }
  };

  try {
    hookJavaAntiAnalysis();
    hookNativeAntiAnalysis();

    log(buildEvent({ metadata, action: "hook_loaded" }));
    send({ type: 'hook_loaded', hook: metadata.name });
    console.log(`[+] ${metadata.name} initialized`);
  } catch (e) {
    console.error(`[${metadata.name}] Initialization failed: ${e}`);
  }
}, {
  name: "hook_anti_analysis",
  entrypoint: "java"
});
