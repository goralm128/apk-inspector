'use strict';

(async function () {
  const metadata = {
    name: "hook_dexloader",
    category: "dex_loading",
    description: "Tracks runtime DEX loading and flags suspicious paths",
    tags: ["java", "dex", "loader", "heuristic"],
    sensitive: true
  };

  const suspiciousPaths = [
    "/sdcard/",
    "/storage/emulated/",
    "/data/local/tmp/",
    "/dev/"
  ];

  const isSuspicious = (path) =>
    typeof path === 'string' && suspiciousPaths.some(p => path.includes(p));

  try {
    const log = await waitForLogger(metadata);

    runWhenJavaIsReady(() => {
      try {
        // Hook DexClassLoader
        const DexCL = Java.use("dalvik.system.DexClassLoader");
        const dexInit = DexCL.$init.overload(
          "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader"
        );

        dexInit.implementation = function (dexPath, optDir, libPath, parent) {
          const dexStr = dexPath?.toString?.() || "null";
          const optStr = optDir?.toString?.() || "null";
          const libStr = libPath?.toString?.() || "null";
          const parentStr = parent?.toString?.() || "null";

          const suspicious = isSuspicious(dexStr) || isSuspicious(optStr);

          log({
            action: "DexClassLoader.init",
            dex_path: dexStr,
            optimized_directory: optStr,
            library_search_path: libStr,
            parent_loader: parentStr,
            suspicious,
            thread: get_thread_name(),
            stack: get_java_stack()
          });

          console.log(`[hook_dexloader] DexClassLoader.init:\n  Dex: ${dexStr}\n  Opt: ${optStr}`);
          return dexInit.call(this, dexPath, optDir, libPath, parent);
        };
        console.log("[hook_dexloader] DexClassLoader hook installed");
      } catch (e) {
        console.error("[hook_dexloader] Failed to hook DexClassLoader:", e);
      }

      try {
        // Hook PathClassLoader
        const PathCL = Java.use("dalvik.system.PathClassLoader");
        const pathInit = PathCL.$init.overload("java.lang.String", "java.lang.ClassLoader");

        pathInit.implementation = function (path, parent) {
          const pathStr = path?.toString?.() || "null";
          const parentStr = parent?.toString?.() || "null";

          const suspicious = isSuspicious(pathStr);

          log({
            action: "PathClassLoader.init",
            dex_path: pathStr,
            parent_loader: parentStr,
            suspicious,
            thread: get_thread_name(),
            stack: get_java_stack()
          });

          console.log(`[hook_dexloader] PathClassLoader.init: ${pathStr}`);
          return pathInit.call(this, path, parent);
        };
        console.log("[hook_dexloader] PathClassLoader hook installed");
      } catch (e) {
        console.error("[hook_dexloader] Failed to hook PathClassLoader:", e);
      }

      send({ type: 'hook_loaded', hook: metadata.name, java: true });
      console.log(`[+] ${metadata.name} initialized`);
    });

  } catch (e) {
    console.error(`[hook_dexloader] Logger setup failed: ${e}`);
  }
})();
