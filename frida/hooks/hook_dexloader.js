'use strict';

const metadata = {
    name: "hook_dexloader",
    category: "dex_loading",
    description: "Tracks runtime DEX loading",
    tags: ["java", "dex", "loader"],
    sensitive: true
};

runWhenJavaIsReady(() => {
    waitForLogger(metadata, (log) => {
        try {
            const D = Java.use("dalvik.system.DexClassLoader");
            D.$init.overload("java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader").implementation = function (dexPath, optDir, lib, parent) {
                log({ hook: metadata.name,
                    action: "dex_load",
                    dex_path: dexPath,
                    optimized_directory: optDir,
                    loader: this.toString()
                });
                return this.$init(dexPath, optDir, lib, parent);
            };
        } catch (e) {
            console.error(`[${metadata.name}] Hook failed: ${e}`);
        }

        send({ type: 'hook_loaded', hook: metadata.name, java: true });
        console.log(`[+] ${metadata.name} initialized`);
    });
});
