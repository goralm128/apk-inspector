'use strict';

const metadata = {
    name: "hook_network_java",
    category: "network",
    description: "Intercepts Java network activity",
    tags: ["java", "network"],
    sensitive: false
};

runWhenJavaIsReady(async () => {
    try {
        const log = await waitForLogger(metadata);

        const URL = Java.use("java.net.URL");
        const HUC = Java.use("java.net.HttpURLConnection");

        // Hook URL.openConnection()
        URL.openConnection.implementation = function () {
            let conn = null;
            try {
                conn = this.openConnection();
                const info = {
                    action: "openConnection",
                    url: this.toString(),
                    connection_type: conn.getClass().getName()
                };
                log(info);
            } catch (e) {
                console.error(`[${metadata.name}] openConnection failed: ${e}`);
            }
            return conn;
        };

        // Optional: Hook connect() to detect actual network usage
        HUC.connect.implementation = function () {
            try {
                const url = this.getURL().toString();
                const method = this.getRequestMethod();
                const headers = {};
                const headerFields = this.getRequestProperties();
                const keys = headerFields.keySet().toArray();

                for (let i = 0; i < keys.length; i++) {
                    const key = keys[i];
                    const values = headerFields.get(key);
                    headers[key] = values ? values.toArray() : [];
                }

                log({
                    action: "connect",
                    url,
                    method,
                    headers
                });
            } catch (e) {
                console.error(`[${metadata.name}] connect() hook failed: ${e}`);
            }

            return this.connect();
        };

        send({ type: 'hook_loaded', hook: metadata.name, java: true });
        console.log(`[+] ${metadata.name} initialized`);

    } catch (e) {
        console.error(`[${metadata.name}] Initialization failed: ${e}`);
    }
});
