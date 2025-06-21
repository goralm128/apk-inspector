'use strict';

maybeRunJavaHook(async () => {
  const metadata = {
    name: "hook_network_java",
    category: "network",
    description: "Intercepts Java network activity including OkHttp, Volley, URLConnection",
    tags: ["java", "network", "http", "okhttp", "volley"],
    sensitive: false,
    entrypoint: "java"
  };

  const log = await waitForLogger(metadata);

  const extractFingerprint = cert => {
    try {
      const enc = cert.getEncoded();
      return Crypto.digest("sha1", enc, { encoding: "hex" });
    } catch (e) {
      return "<fingerprint-failed>";
    }
  };

  // ─── URLConnection ─────────────────────────────
  const URL = Java.use("java.net.URL");
  URL.openConnection.implementation = function () {
    const conn = this.openConnection();
    try {
      log(buildEvent({
        metadata,
        action: "URL.openConnection",
        args: {
          url: this.toString(),
          connection_type: conn.getClass().getName()
        },
        context: { stack: get_java_stack() }
      }));
    } catch (e) {
      console.error(`[${metadata.name}] openConnection logging failed: ${e}`);
    }
    return conn;
  };
  console.log(`[${metadata.name}] Hooked URL.openConnection`);

  const HttpURLConnection = Java.use("java.net.HttpURLConnection");
  HttpURLConnection.connect.implementation = function () {
    const url = this.getURL()?.toString() || "<unknown>";
    const method = this.getRequestMethod() || "<unknown>";
    const headers = {};

    try {
      const props = this.getRequestProperties();
      const keys = props.keySet().toArray();
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        const values = props.get(key);
        headers[key] = values ? values.toArray() : [];
      }
    } catch (e) {
      console.warn(`[${metadata.name}] Header parse failed: ${e}`);
    }

    log(buildEvent({
      metadata,
      action: "HttpURLConnection.connect",
      args: { url, method, headers },
      context: { stack: get_java_stack() }
    }));

    try {
      this.connect();

      const respHeaders = {};
      const fields = this.getHeaderFields();
      const keys = fields.keySet().toArray();
      for (const k of keys) {
        const vals = fields.get(k);
        if (k !== null) {
          respHeaders[k] = vals ? vals.toArray() : [];
        }
      }

      log(buildEvent({
        metadata,
        action: "HttpURLConnection.responseHeaders",
        args: { headers: respHeaders }
      }));

      const conn = Java.cast(this, Java.use("javax.net.ssl.HttpsURLConnection"));
      const certs = conn.getServerCertificates();
      const fingerprints = Array.from(certs).map(extractFingerprint);

      log(buildEvent({
        metadata,
        action: "SSL.cert_fingerprint",
        args: { fingerprints }
      }));

    } catch (e) {
      console.warn(`[${metadata.name}] connect() failed: ${e}`);
    }

    return;
  };
  console.log(`[${metadata.name}] Hooked HttpURLConnection.connect`);

  // ─── OkHttp ─────────────────────────────────────
  Java.enumerateLoadedClasses({
    onMatch(name) {
      if (name === "okhttp3.Request") {
        try {
          const Request = Java.use("okhttp3.Request");
          Request.toString.implementation = function () {
            const str = this.toString();
            log(buildEvent({
              metadata,
              action: "OkHttp.Request.toString",
              args: { request: str },
              context: { stack: get_java_stack() }
            }));
            return str;
          };
          console.log(`[${metadata.name}] Hooked okhttp3.Request.toString`);
        } catch (e) {
          console.error(`[${metadata.name}] OkHttp hook error: ${e}`);
        }
      }
    },
    onComplete() {}
  });

  // ─── Volley ─────────────────────────────────────
  Java.enumerateLoadedClasses({
    onMatch(name) {
      if (name === "com.android.volley.toolbox.StringRequest") {
        try {
          const StringRequest = Java.use("com.android.volley.toolbox.StringRequest");
          StringRequest.getUrl.implementation = function () {
            const url = this.getUrl();
            log(buildEvent({
              metadata,
              action: "Volley.StringRequest.getUrl",
              args: { url },
              context: { stack: get_java_stack() }
            }));
            return url;
          };
          console.log(`[${metadata.name}] Hooked Volley StringRequest.getUrl`);
        } catch (e) {
          console.error(`[${metadata.name}] Volley hook error: ${e}`);
        }
      }
    },
    onComplete() {}
  });

  log(buildEvent({ metadata, action: "hook_loaded" }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized`);
}, {
  name: "hook_network_java",
  entrypoint: "java"
});
