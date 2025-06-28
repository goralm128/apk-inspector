'use strict';

/**
 * hook_dex_monitor.js
 *
 * Unified DEX loader detector and dumper.
 * Hooks `open` and `mmap` to detect suspicious DEX activity and dump memory-mapped DEX files.
 * Replaces: hook_dex_memory_loader.js, bootstrap_native.js, hook_dump_dex_from_mmap.js
 */

(async function () {
  const metadata = {
    name: "hook_dex_monitor",
    category: "dex_loading",
    description: "Unified monitor for DEX memory loading and dumping",
    tags: ["native", "dex", "mmap", "dump", "memory"],
    sensitive: true,
    entrypoint: "native"
  };

  const log = await waitForLogger(metadata);
  const DEX_MAGIC = [0x64, 0x65, 0x78, 0x0A]; // 'dex\n'
  const DUMP_DIR = "/data/local/tmp";

  const readSafe = ptr => {
    try { return ptr.readUtf8String(); } catch { return "<invalid>"; }
  };

  const getDexSize = ptr => {
    try { return ptr.add(0x20).readU32(); } catch { return 0; }
  };

  const dumpDex = (ptr, size) => {
    try {
      const timestamp = Date.now();
      const path = `${DUMP_DIR}/dump_${timestamp}.dex`;
      const bytes = Memory.readByteArray(ptr, size);
      const file = new File(path, "wb");
      file.write(bytes); file.flush(); file.close();
      return path;
    } catch (e) {
      console.error(`[hook_dex_monitor] Dump failed: ${e}`);
      return null;
    }
  };

  await safeAttach("open", {
    onEnter(args) {
      this.path = normalizePath(readSafe(args[0]));
    },
    onLeave(retval) {
      if (!this.path) return;
      const suspicious = [".dex", "/tmp", "/dev", "/sdcard", "/data/local"].some(p => this.path.includes(p));
      if (suspicious) {
        log(buildEvent({
          metadata,
          action: "open",
          args: {
            path: this.path,
            fd: retval?.toInt32?.() ?? -1
          },
          suspicious
        }));
        console.log(`[hook_dex_monitor] open(): ${this.path}`);
      }
    }
  }, null, {
    maxRetries: 8,
    retryInterval: 250,
    verbose: true
  });

  await safeAttach("mmap", {
    onEnter(args) {
      this.length = args[1]?.toInt32?.() ?? 0;
      this.prot = args[2]?.toInt32?.() ?? 0;
      this.ctx = this.context;
    },
    onLeave(retval) {
      if (retval.isNull()) return;

      try {
        const head = Memory.readByteArray(retval, 4);
        const magic = Array.from(new Uint8Array(head || []));
        if (magic.toString() === DEX_MAGIC.toString()) {
          const dexSize = getDexSize(retval);
          const dumpPath = dumpDex(retval, dexSize);
          const event = buildEvent({
            metadata,
            action: "mmap_dex",
            args: {
              addr: retval.toString(),
              length: this.length,
              protection: this.prot,
              dex_size: dexSize,
              dump_path: dumpPath || "<failed>"
            },
            context: { stack: formatBacktrace(this.ctx) },
            suspicious: true
          });
          log(event);
          if (dumpPath) {
            send({ type: "dex_dumped", path: dumpPath, size: dexSize });
            console.warn(`[hook_dex_monitor] Dumped DEX: ${dumpPath} (${dexSize} bytes)`);
          } else {
            console.warn(`[hook_dex_monitor] DEX dump failed`);
          }
        }
      } catch (e) {
        console.error(`[hook_dex_monitor] mmap handler error: ${e}`);
      }
    }
  }, null, {
    maxRetries: 8,
    retryInterval: 250,
    verbose: true
  });

  log(buildEvent({ metadata, action: "hook_loaded" }));
  send({ type: "hook_loaded", hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized`);
})();
