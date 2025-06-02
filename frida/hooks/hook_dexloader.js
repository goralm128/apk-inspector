'use strict';

/**
 * Hook Metadata
 */
const metadata = {
    name: "hook_dexloader",
    sensitive: true,
    tags: ["java", "dex", "loader", "runtime"]
};

Java.perform(function () {
    const logDex = createHookLogger({
        hook: "DexClassLoader.$init",
        category: "reflection", // or "dynamic_loading"
        tags: metadata.tags,
        description: "Hooks DexClassLoader constructor",
        sensitive: metadata.sensitive
    });
    /**
     * Hooks the DexClassLoader constructor to log dex loading events.
     * This is useful for monitoring dynamic class loading in Android applications.
     */
    const DexClassLoader = Java.use("dalvik.system.DexClassLoader");

    DexClassLoader.$init.overload("java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader").implementation = function (dexPath, optimizedDir, libSearchPath, parent) {
        logDex({
            action: "dex_load",
            dex_path: dexPath,
            optimized_directory: optimizedDir
        });
        return this.$init(dexPath, optimizedDir, libSearchPath, parent);
    };
});
