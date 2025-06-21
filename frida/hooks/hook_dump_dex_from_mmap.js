'use strict';

(async function () {
  const metadata = {
    name: "hook_dump_dex_from_mmap",
    category: "dex_dump",
    description: "Detects and dumps in-memory DEX files loaded via mmap",
    tags: ["native", "dex", "memory", "forensics", "dump"],
    sensitive: true,
    entrypoint: "native"
  };

  const log = createHookLogger(metadata);
  const DEX_MAGIC = [0x64, 0x65, 0x78, 0x0A]; // 'dex\n'
  const DUMP_DIR = "/data/local/tmp";

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

  function readDexLength(ptr) {
    try {
      const len = ptr.add(0x20).readU32(); // DEX length is at offset 0x20
      return len;
    } catch (e) {
      return 0;
    }
  }

  function writeDexToFile(basePtr, size, dumpPath) {
    try {
      const dexBytes = Memory.readByteArray(basePtr, size);
      const file = new File(dumpPath, "wb");
      file.write(dexBytes);
      file.flush();
      file.close();
      return true;
    } catch (e) {
      console.error(`[hook_dump_dex_from_mmap] writeDexToFile failed: ${e.message}`);
      return false;
    }
  }

  const mmapAddr = Module.findExportByName("libc.so", "mmap");
  if (!mmapAddr) {
    console.error("[bootstrap_native] mmap() not found in libc.so");
    return;
  }

  await safeAttach("mmap", {
    onEnter(args) {
      this.length = args[1].toInt32();
      this.prot = args[2].toInt32();
      this.flags = args[3].toInt32();
      this.ctx = this.context;
    },
    onLeave(retval) {
      if (retval.isNull()) return;

      try {
        const header = Memory.readByteArray(retval, 4);
        const magic = header ? Array.from(new Uint8Array(header)) : [];

        if (magic.toString() === DEX_MAGIC.toString()) {
          const dexSize = readDexLength(retval);
          const timestamp = Date.now();
          const dumpPath = `${DUMP_DIR}/dump_${timestamp}.dex`;

          const success = writeDexToFile(retval, dexSize, dumpPath);

          const ev = buildEvent({
            metadata,
            action: "dump_dex",
            context: { stack: getBacktrace(this.ctx) },
            args: {
              mmap_retval: retval.toString(),
              dex_size: dexSize,
              dump_path: dumpPath
            },
            suspicious: true
          });

          log(ev);
          send({ status: success ? "dumped" : "failed", path: dumpPath, size: dexSize, hook: metadata.name });

          if (success) {
            console.warn(`[hook_dump_dex_from_mmap] Dumped DEX → ${dumpPath} (${dexSize} bytes)`);
          }
        }
      } catch (e) {
        console.error(`[hook_dump_dex_from_mmap] Error processing mmap(): ${e.message}`);
      }
    }
  }, null, {
    maxRetries: 8,
    retryInterval: 200,
    verbose: true
  });

  log(buildEvent({ metadata, action: "hook_loaded" }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log("[+] hook_dump_dex_from_mmap initialized");
})();
