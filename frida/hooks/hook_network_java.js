'use strict';

/**
 * Hook Metadata
 */
const metadata = {
    name: "hook_network_java",
    sensitive: false,
    tags: ["java", "network"]
};

Java.perform(function () {
    const logNetworkJava = createHookLogger({
        hook: "URL.openConnection",
        category: "network",
        tags: metadata.tags,
        description: "Hooks java.net.URL.openConnection",
        sensitive: metadata.sensitive
    });

    try {
        const URLClass = Java.use("java.net.URL");
        URLClass.openConnection.implementation = function () {
            const conn = this.openConnection();
            logNetworkJava({
                action: "openConnection",
                url: this.toString()
            });
            return conn;
        };
    } catch (e) {
        console.error("Failed to hook java.net.URL", e);
    }
});
