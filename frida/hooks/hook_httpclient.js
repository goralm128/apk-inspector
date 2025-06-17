'use strict';

(async function () {
  const metadata = {
    name: "hook_httpclient",
    category: "network",
    description: "Intercepts Apache HttpClient usage",
    tags: ["java", "network", "apache", "httpclient"],
    sensitive: true
  };

  function isSuspiciousUrl(url) {
    if (!url) return false;

    const suspiciousTLDs = /\.(ru|cn|xyz|tk|pw|top)$/i;
    const suspiciousPaths = /(\/gate\.php|\/upload|\/report|\/cmd|\/shell)/i;
    const privateIPs = /^(http|https):\/\/(127\.0\.0\.1|10\.|192\.168|172\.(1[6-9]|2[0-9]|3[0-1]))/;
    const base64Pattern = /[A-Za-z0-9+/]{50,}={0,2}/;

    return suspiciousTLDs.test(url) ||
           suspiciousPaths.test(url) ||
           privateIPs.test(url) ||
           base64Pattern.test(url);
  }

  try {
    const log = await waitForLogger(metadata);

    runWhenJavaIsReady(() => {
      try {
        // Hook HttpClient.execute(HttpUriRequest)
        const HttpClient = Java.use("org.apache.http.impl.client.DefaultHttpClient");
        const execute = HttpClient.execute.overload("org.apache.http.client.methods.HttpUriRequest");

        execute.implementation = function (request) {
          let url = "<unknown>";
          let method = "<unknown>";
          let suspicious = false;

          try {
            method = request.getMethod();
            url = request.getURI().toString();
            suspicious = isSuspiciousUrl(url);
          } catch (e) {
            console.warn(`[hook_httpclient] Failed to parse request: ${e}`);
          }

          log({
            action: "httpclient.execute",
            method,
            url,
            suspicious,
            thread: get_thread_name(),
            stack: get_java_stack()
          });

          console.log(`[hook_httpclient] ${method} → ${url}`);
          return execute.call(this, request);
        };

        console.log("[hook_httpclient] execute() hook installed");

        // Hook setEntity to log POST bodies
        const EntityRequest = Java.use("org.apache.http.client.methods.HttpEntityEnclosingRequestBase");
        const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");

        EntityRequest.setEntity.implementation = function (entity) {
          try {
            const baos = ByteArrayOutputStream.$new();
            entity.writeTo(baos);
            const body = baos.toString(); // assumes default charset
            const suspicious = isSuspiciousUrl(body);

            log({
              action: "httpclient.setEntity",
              payload: body.slice(0, 300),
              suspicious,
              thread: get_thread_name(),
              stack: get_java_stack()
            });

            console.log(`[hook_httpclient] Captured POST body: ${body.slice(0, 100)}...`);
          } catch (e) {
            console.error(`[hook_httpclient] Failed to extract POST payload: ${e}`);
          }

          return this.setEntity(entity);
        };

        console.log("[hook_httpclient] setEntity() hook installed");

        send({ type: "hook_loaded", hook: metadata.name, java: true });
        console.log(`[+] ${metadata.name} initialized`);

      } catch (hookErr) {
        console.error(`[hook_httpclient] Hooking failed: ${hookErr}`);
      }
    });

  } catch (e) {
    console.error(`[hook_httpclient] Logger setup failed: ${e}`);
  }
})();
