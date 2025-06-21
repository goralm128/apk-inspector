'use strict';

maybeRunJavaHook(async () => {
  const metadata = {
    name: "hook_dexloader",
    category: "dex_loading",
    description: "Tracks runtime DEX loading and flags suspicious paths",
    tags: ["java", "dex", "loader", "heuristic"],
    sensitive: true,
    entrypoint: "java"
  };

  const suspiciousPaths = [
    "/sdcard/", "/storage/emulated/", "/data/local/tmp/", "/dev/"
  ];

  const isSuspicious = path =>
    typeof path === 'string' && suspiciousPaths.some(p => path.includes(p));

  const log = await waitForLogger(metadata);

  const DexCL = Java.use("dalvik.system.DexClassLoader");
  const dexInit = DexCL.$init.overload(
    "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader"
  );

  dexInit.implementation = function (dexPath, optDir, libPath, parent) {
    const dexStr = dexPath?.toString?.() || "null";
    const optStr = optDir?.toString?.() || "null";
    const libStr = libPath?.toString?.() || "null";
    const parentStr = parent?.toString?.() || "null";

    log(buildEvent({
      metadata,
      action: "DexClassLoader.init",
      context: { stack: get_java_stack() },
      args: {
        dex_path: dexStr,
        optimized_directory: optStr,
        library_search_path: libStr,
        parent_loader: parentStr
      },
      suspicious: isSuspicious(dexStr) || isSuspicious(optStr)
    }));

    console.log(`[${metadata.name}] DexClassLoader.init:\n  Dex: ${dexStr}\n  Opt: ${optStr}`);
    return dexInit.call(this, dexPath, optDir, libPath, parent);
  };
  console.log(`[${metadata.name}] DexClassLoader hook installed`);

  const PathCL = Java.use("dalvik.system.PathClassLoader");
  const pathInit = PathCL.$init.overload("java.lang.String", "java.lang.ClassLoader");

  pathInit.implementation = function (path, parent) {
    const pathStr = path?.toString?.() || "null";
    const parentStr = parent?.toString?.() || "null";

    log(buildEvent({
      metadata,
      action: "PathClassLoader.init",
      context: { stack: get_java_stack() },
      args: {
        dex_path: pathStr,
        parent_loader: parentStr
      },
      suspicious: isSuspicious(pathStr)
    }));

    console.log(`[${metadata.name}] PathClassLoader.init: ${pathStr}`);
    return pathInit.call(this, path, parent);
  };
  console.log(`[${metadata.name}] PathClassLoader hook installed`);

  log(buildEvent({ metadata, action: "hook_loaded" }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized`);
}, {
  name: "hook_dexloader",
  entrypoint: "java"
});
