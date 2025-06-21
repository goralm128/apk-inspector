'use strict';

(async function () {
  const metadata = {
    name: "hook_jni",
    category: "native",
    description: "Tracks native process forks using fork(), clone(), and vfork()",
    tags: ["native", "fork", "clone", "process", "sandbox", "anti-frida"],
    sensitive: false,
    entrypoint: "native"
  };

  const log = createHookLogger(metadata);

  const hookList = ["fork", "clone", "vfork"];
  const hooked = [];

  for (const fn of hookList) {
    try {
      await safeAttach(fn, {
        onEnter(args) {
          this.parentPid = Process.id;
          this.fn = fn;
        },
        onLeave(retval) {
          const childPid = retval?.toInt32?.();
          if (childPid === 0) return; // Inside child process; ignore

          const event = buildEvent({
            metadata,
            action: `native_fork`,
            args: {
              function: this.fn,
              parent_pid: this.parentPid,
              child_pid: childPid
            },
            context: {
              stack: Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress)
                .slice(0, 8)
                .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`),
            },
            suspicious: false
          });

          log(event);
          send({ type: "fork_detected", function: this.fn, child_pid: childPid, parent_pid: this.parentPid });
          console.log(`[hook_jni] ${this.fn}(): parent=${this.parentPid} → child=${childPid}`);
        }
      }, null, {
        maxRetries: 5,
        retryInterval: 250,
        verbose: true
      });

      console.log(`[hook_jni] Hooked ${fn}()`);
      hooked.push(fn);

    } catch (err) {
      console.warn(`[hook_jni] Failed to hook ${fn}: ${err.message}`);
    }
  }

  log(buildEvent({
    metadata,
    action: "hook_loaded",
    args: { hooked }
  }));

  send({ type: 'hook_loaded', hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized`);
})();
