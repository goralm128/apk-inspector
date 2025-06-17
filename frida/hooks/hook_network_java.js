'use strict';

(async function () {
  const metadata = {
    name: "hook_network_java",
    category: "network",
    description: "Intercepts Java network activity including OkHttp and Volley",
    tags: ["java", "network", "okhttp", "volley", "http"],
    sensitive: false,
    entrypoint: "java"
  };

  try {
    const log = await waitForLogger(metadata);

    runWhenJavaIsReady(() => {
      try {
        // --- java.net.URL.openConnection ---
        const URL = Java.use("java.net.URL");
        URL.openConnection.implementation = function () {
          const conn = this.openConnection();
          try {
            log({
              action: "URL.openConnection",
              url: this.toString(),
              connection_type: conn.getClass().getName(),
              thread: get_thread_name(),
              stack: get_java_stack()
            });
          } catch (e) {
            console.error(`[hook_network_java] openConnection error: ${e}`);
          }
          return conn;
        };
        console.log("[hook_network_java] Hooked java.net.URL.openConnection");

        // --- java.net.HttpURLConnection.connect ---
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
          } catch (e) {
            console.error(`[hook_network_java] HttpURLConnection.connect error: ${e}`);
          }

          return this.connect();
        };
        console.log("[hook_network_java] Hooked HttpURLConnection.connect");

        // --- OkHttp: okhttp3.Request.toString ---
        Java.enumerateLoadedClasses({
          onMatch(name) {
            if (name === "okhttp3.Request") {
              try {
                const Request = Java.use("okhttp3.Request");
                Request.toString.implementation = function () {
                  const str = this.toString();
                  log({
                    action: "OkHttp.Request.toString",
                    request: str,
                    thread: get_thread_name(),
                    stack: get_java_stack()
                  });
                  return str;
                };
                console.log("[hook_network_java] Hooked okhttp3.Request.toString");
              } catch (e) {
                console.error("[hook_network_java] OkHttp hook failed:", e);
              }
            }
          },
          onComplete() {}
        });

        // --- Volley: com.android.volley.toolbox.StringRequest ---
        Java.enumerateLoadedClasses({
          onMatch(name) {
            if (name === "com.android.volley.toolbox.StringRequest") {
              try {
                const StringRequest = Java.use("com.android.volley.toolbox.StringRequest");
                StringRequest.getUrl.implementation = function () {
                  const url = this.getUrl();
                  log({
                    action: "Volley.StringRequest.getUrl",
                    url,
                    thread: get_thread_name(),
                    stack: get_java_stack()
                  });
                  return url;
                };
                console.log("[hook_network_java] Hooked Volley StringRequest.getUrl");
              } catch (e) {
                console.error("[hook_network_java] Volley hook failed:", e);
              }
            }
          },
          onComplete() {}
        });

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
