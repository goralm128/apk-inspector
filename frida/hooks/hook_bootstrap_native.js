'use strict';

(async function () {
  const metadata = {
    name: "bootstrap_native",
    category: "dex_loading",
    description: "Early native hook to detect memory-mapped or encrypted .dex loads before Java VM is ready",
    tags: ["native", "dex", "mmap", "early"],
    sensitive: true,
    entrypoint: "native"
  };

  const log = createHookLogger(metadata);

  function readSafeUtf8(ptr) {
    try { return ptr.readUtf8String(); }
    catch (_) { return "<unreadable>"; }
  }

  function getBacktrace(ctx) {
    try {
      return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .slice(0, 10)
        .map(sym => `${sym.moduleName || "?"}!${sym.name || "?"}@${sym.address}`);
    } catch (_) {
      return ["<no backtrace>"];
    }
  }

  const suspiciousPaths = [
    "/data/local/tmp", "/sdcard", "/storage/emulated", "/dev/", ".dex"
  ];

  const isSuspicious = (path) => {
    return suspiciousPaths.some(p => path.includes(p));
  };

  // Hook open()
  try {
    await safeAttach("open", {
      onEnter(args) {
        this.path = readSafeUtf8(args[0]);
        this.ctx = this.context;
      },
      onLeave(retval) {
        if (!this.path) return;
        const match = isSuspicious(this.path);
        const ev = buildEvent({
          metadata,
          action: "open",
          context: { stack: getBacktrace(this.ctx) },
          args: {
            path: this.path,
            retval: retval?.toInt32?.() ?? -1
          },
          suspicious: match
        });
        log(ev);
        if (match) {
          console.warn(`[bootstrap_native] suspicious open(): ${this.path}`);
        } else {
          console.log(`[bootstrap_native] open(): ${this.path}`);
        }
      }
    }, null, { maxRetries: 6, verbose: true });
    console.log("[bootstrap_native] open() hooked");
  } catch (e) {
    console.error(`[bootstrap_native] failed to hook open(): ${e}`);
  }

  const mmapAddr = Module.findExportByName("libc.so", "mmap");
  if (!mmapAddr) {
    console.error("[bootstrap_native] mmap() not found in libc.so");
    return;
  }

  // Hook mmap()
  try {
    await safeAttach("mmap", {
      onEnter(args) {
        this.length = args[1].toInt32();
        this.prot = args[2].toInt32();
        this.ctx = this.context;
      },
      onLeave(retval) {
        if (retval.isNull()) return;

        try {
          const header = Memory.readByteArray(retval, 4);
          const bytes = header ? Array.from(new Uint8Array(header)) : [];

          if (bytes[0] === 0x64 && bytes[1] === 0x65 && bytes[2] === 0x78 && bytes[3] === 0x0A) {
            const ev = buildEvent({
              metadata,
              action: "mmap_dex",
              context: { stack: getBacktrace(this.ctx) },
              args: {
                length: this.length,
                protection: this.prot,
                addr: retval.toString()
              },
              suspicious: true
            });
            log(ev);
            console.warn(`[bootstrap_native] mmap() loaded .dex at ${retval}`);
          }
        } catch (e) {
          console.error(`[bootstrap_native] mmap() error: ${e}`);
        }
      }
    }, null, { maxRetries: 6, verbose: true });
    console.log("[bootstrap_native] mmap() hooked");
  } catch (e) {
    console.error(`[bootstrap_native] failed to hook mmap(): ${e}`);
  }

  log(buildEvent({ metadata, action: "hook_loaded" }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized`);
})();
