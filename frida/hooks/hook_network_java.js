'use strict';

const metadata = {
    name: "hook_network_java",
    category: "network",
    description: "Intercepts Java network activity",
    tags: ["java", "network"],
    sensitive: false
};

runWhenJavaIsReady(() => {
    waitForLogger(metadata, (log) => {
        try {
            const U = Java.use("java.net.URL");
            U.openConnection.implementation = function () {
                const conn = this.openConnection();
                log({ hook: metadata.name, action: "openConnection", url: this.toString() });
                return conn;
            };
        } catch (e) {
            console.error(`[${metadata.name}] Hook failed: ${e}`);
        }

        send({ type: 'hook_loaded', hook: metadata.name, java: true });
        console.log(`[+] ${metadata.name} initialized`);
    });
});
