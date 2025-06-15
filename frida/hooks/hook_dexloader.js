'use strict';

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

function isSuspiciousPath(path) {
    if (!path) return false;
    return suspiciousPaths.some(suspicious => path.includes(suspicious));
}

runWhenJavaIsReady(async () => {
    try {
        const log = await waitForLogger(metadata);

        // DexClassLoader
        const DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        const dexInit = DexClassLoader.$init.overload(
            "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader"
        );

        dexInit.implementation = function (dexPath, optDir, libPath, parent) {
            const suspicious = isSuspiciousPath(dexPath) || isSuspiciousPath(optDir);

            log({
                action: "DexClassLoader.init",
                dex_path: dexPath,
                optimized_directory: optDir,
                library_search_path: libPath,
                parent_loader: parent?.toString() || "null",
                suspicious,
                thread: get_thread_name(),
                stack: get_java_stack()
            });

            return dexInit.call(this, dexPath, optDir, libPath, parent);
        };

        // PathClassLoader
        const PathClassLoader = Java.use("dalvik.system.PathClassLoader");
        const pathInit = PathClassLoader.$init.overload(
            "java.lang.String", "java.lang.ClassLoader"
        );

        pathInit.implementation = function (path, parent) {
            const suspicious = isSuspiciousPath(path);

            log({
                action: "PathClassLoader.init",
                dex_path: path,
                parent_loader: parent?.toString() || "null",
                suspicious,
                thread: get_thread_name(),
                stack: get_java_stack()
            });

            return pathInit.call(this, path, parent);
        };

        send({ type: 'hook_loaded', hook: metadata.name, java: true });
        console.log(`[+] ${metadata.name} initialized`);
    } catch (e) {
        console.error(`[${metadata.name}] Initialization failed: ${e}`);
    }
});
