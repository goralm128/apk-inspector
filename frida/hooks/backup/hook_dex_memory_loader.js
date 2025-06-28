'use strict';

(async function () {
  const metadata = {
    name: "hook_dex_memory_loader",
    category: "dex_loading",
    description: "Detects memory-mapped or encrypted .dex files loaded at runtime",
    tags: ["native", "dex", "encrypted", "memload"],
    sensitive: true,
    entrypoint: "native"
  };

  const log = await waitForLogger(metadata);

  function readUtf8Safe(ptr) {
    try {
      return ptr.readUtf8String();
    } catch (_) {
      return "<invalid>";
    }
  }

  const isSuspiciousPath = path => (
    path.endsWith(".dex") ||
    path.includes("/data/local/tmp/") ||
    path.includes("/sdcard/") ||
    path.includes("/mnt/") ||
    path.includes("/dev/")
  );

  // ───── Hook open() ─────
  const openAddr = Module.findExportByName(null, 'open');
  if (openAddr) {
    Interceptor.attach(openAddr, {
      onEnter(args) {
        this.path = readUtf8Safe(args[0]);
      },
      onLeave(retval) {
        if (!this.path) return;
        if (isSuspiciousPath(this.path)) {
          log(buildEvent({
            metadata,
            action: "open",
            args: { path: this.path },
            suspicious: true
          }));
          console.log(`[hook_dex_memory_loader] open() → ${this.path}`);
        }
      }
    });
    console.log("[hook_dex_memory_loader] Hooked open()");
  } else {
    console.warn("[hook_dex_memory_loader] open() symbol not found.");
  }

  // ───── Hook mmap() ─────
  const mmapAddr = Module.findExportByName(null, 'mmap');
  if (mmapAddr) {
    Interceptor.attach(mmapAddr, {
      onEnter(args) {
        this.length = args[1]?.toInt32?.() ?? -1;
        this.prot = args[2]?.toInt32?.() ?? -1;
      },
      onLeave(retval) {
        if (retval.isNull()) return;

        try {
          const bytes = Memory.readByteArray(retval, 8);
          const magic = new Uint8Array(bytes);
          const isDex = magic[0] === 0x64 && magic[1] === 0x65 && magic[2] === 0x78 && magic[3] === 0x0A;

          if (isDex) {
            log(buildEvent({
              metadata,
              action: "mmap",
              args: {
                addr: retval.toString(),
                length: this.length,
                protection: this.prot
              },
              suspicious: true
            }));
            console.log(`[hook_dex_memory_loader] mmap() loaded DEX at ${retval} len=${this.length}`);
          }
        } catch (err) {
          console.warn(`[hook_dex_memory_loader] mmap read error: ${err.message}`);
        }
      }
    });
    console.log("[hook_dex_memory_loader] Hooked mmap()");
  } else {
    console.warn("[hook_dex_memory_loader] mmap() symbol not found.");
  }

  log(buildEvent({ metadata, action: "hook_loaded", args: {} }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized`);
})();
