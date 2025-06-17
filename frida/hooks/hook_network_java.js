'use strict';

(async function () {
  const metadata = {
    name: "hook_network_java",
    category: "network",
    description: "Intercepts Java network activity",
    tags: ["java", "network"],
    sensitive: false
  };

  try {
    const log = await waitForLogger(metadata);

    runWhenJavaIsReady(() => {
      try {
        // === Hook java.net.URL.openConnection() ===
        const URL = Java.use("java.net.URL");

        URL.openConnection.implementation = function () {
          let conn;
          try {
            conn = this.openConnection();

            const info = {
              action: "URL.openConnection",
              url: this.toString(),
              connection_type: conn.getClass().getName(),
              thread: get_thread_name(),
              stack: get_java_stack()
            };

            console.log(`[hook_network_java] URL.openConnection → ${info.connection_type}`);
            log(info);
          } catch (e) {
            console.error(`[hook_network_java] URL.openConnection error: ${e}`);
          }

          return conn;
        };

        console.log("[hook_network_java] Hooked java.net.URL.openConnection");

        // === Hook java.net.HttpURLConnection.connect() ===
        const HttpURLConnection = Java.use("java.net.HttpURLConnection");

        HttpURLConnection.connect.implementation = function () {
          try {
            const url = this.getURL().toString();
            const method = this.getRequestMethod();
            const headers = {};
            const props = this.getRequestProperties();
            const keys = props.keySet().toArray();

            for (let i = 0; i < keys.length; i++) {
              const key = keys[i];
              const values = props.get(key);
              headers[key] = values ? values.toArray() : [];
            }

            log({
              action: "HttpURLConnection.connect",
              url,
              method,
              headers,
              thread: get_thread_name(),
              stack: get_java_stack()
            });

            console.log(`[hook_network_java] Connecting: ${method} ${url}`);
          } catch (e) {
            console.error(`[hook_network_java] connect() logging failed: ${e}`);
          }

          return this.connect();
        };

        console.log("[hook_network_java] Hooked HttpURLConnection.connect");

        send({ type: 'hook_loaded', hook: metadata.name, java: true });
        console.log(`[+] ${metadata.name} initialized`);

      } catch (hookErr) {
        console.error(`[hook_network_java] Hook installation error: ${hookErr}`);
      }
    });

  } catch (e) {
    console.error(`[hook_network_java] Logger setup failed: ${e}`);
  }
})();
