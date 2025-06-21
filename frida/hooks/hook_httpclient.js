'use strict';

maybeRunJavaHook(async () => {
  const metadata = {
    name: "hook_httpclient",
    category: "network",
    description: "Intercepts Apache HttpClient usage including requests, bodies, and response headers",
    tags: ["java", "network", "apache", "httpclient", "ssl"],
    sensitive: true,
    entrypoint: "java"
  };

  const isSuspiciousUrl = url => {
    if (!url) return false;
    const suspiciousTLDs = /\.(ru|cn|xyz|tk|pw|top)$/i;
    const suspiciousPaths = /(\/gate\.php|\/upload|\/report|\/cmd|\/shell)/i;
    const privateIPs = /^(http|https):\/\/(127\.0\.0\.1|10\.|192\.168|172\.(1[6-9]|2[0-9]|3[0-1]))/;
    const base64Pattern = /[A-Za-z0-9+/]{50,}={0,2}/;
    return suspiciousTLDs.test(url) || suspiciousPaths.test(url) || privateIPs.test(url) || base64Pattern.test(url);
  };

  const extractFingerprint = cert => {
    try {
      const enc = cert.getEncoded();
      return Crypto.digest("sha1", enc, { encoding: "hex" });
    } catch (e) {
      return "<fingerprint-failed>";
    }
  };

  const log = await waitForLogger(metadata);

  const HttpClient = Java.use("org.apache.http.impl.client.DefaultHttpClient");
  const execute = HttpClient.execute.overload("org.apache.http.client.methods.HttpUriRequest");

  execute.implementation = function (request) {
    let url = "<unknown>", method = "<unknown>", suspicious = false;

    try {
      method = request.getMethod();
      url = request.getURI().toString();
      suspicious = isSuspiciousUrl(url);
    } catch (e) {
      console.warn(`[${metadata.name}] Failed to parse request: ${e}`);
    }

    log(buildEvent({
      metadata,
      action: "httpclient.execute",
      context: { stack: get_java_stack() },
      args: { method, url: url.slice(0, 512), suspicious }
    }));

    console.log(`[${metadata.name}] ${method} → ${url}`);

    const response = execute.call(this, request);

    try {
      const headers = {};
      const allHeaders = response.getAllHeaders();
      for (let i = 0; i < allHeaders.length; i++) {
        headers[allHeaders[i].getName()] = allHeaders[i].getValue();
      }

      log(buildEvent({
        metadata,
        action: "httpclient.responseHeaders",
        args: { headers }
      }));
    } catch (e) {
      console.error(`[${metadata.name}] Failed to extract response headers: ${e}`);
    }

    try {
      const conn = response.getParams().getParameter("http.connection");
      if (conn) {
        const sslSocket = Java.cast(conn.getSocket(), Java.use("javax.net.ssl.SSLSocket"));
        const session = sslSocket.getSession();
        const certs = session.getPeerCertificates();
        const fingerprints = Array.from(certs).map(extractFingerprint);

        log(buildEvent({
          metadata,
          action: "httpclient.ssl.fingerprint",
          args: { fingerprints }
        }));
      }
    } catch (e) {
      console.error(`[${metadata.name}] SSL fingerprint extraction failed: ${e}`);
    }

    return response;
  };

  const EntityRequest = Java.use("org.apache.http.client.methods.HttpEntityEnclosingRequestBase");
  const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");

  EntityRequest.setEntity.implementation = function (entity) {
    try {
      const baos = ByteArrayOutputStream.$new();
      entity.writeTo(baos);
      const body = baos.toString();
      const suspicious = isSuspiciousUrl(body);

      log(buildEvent({
        metadata,
        action: "httpclient.setEntity",
        context: { stack: get_java_stack() },
        args: { payload: body.slice(0, 300), suspicious }
      }));

      console.log(`[${metadata.name}] Captured POST body: ${body.slice(0, 100)}...`);
    } catch (e) {
      console.error(`[${metadata.name}] Failed to extract POST payload: ${e}`);
    }

    return this.setEntity(entity);
  };

  log(buildEvent({ metadata, action: "hook_loaded" }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized`);
}, {
  name: "hook_httpclient",
  entrypoint: "java"
});
