'use strict';

maybeRunJavaHook(async () => {
  const metadata = {
    name: "hook_webview",
    category: "webview",
    description: "Monitors WebView API usage, JS bridges, URL loading, HTML injection",
    tags: ["java", "webview", "url", "html", "js", "bridge", "c2", "phishing"],
    sensitive: true,
    entrypoint: "java"
  };

  const log = await waitForLogger(metadata);
  const WebView = Java.use("android.webkit.WebView");

  const suspiciousDomains = /\.(ru|cn|tk|xyz|pw|top|ml|ga|cf|gq)$/i;
  const suspiciousPaths = /\/(cmd|admin|login|panel|gate|upload|hook|update|backdoor)\b/i;

  const isSuspiciousUrl = (url) =>
    typeof url === "string" &&
    (suspiciousDomains.test(url) || suspiciousPaths.test(url));

  // ─── WebView.loadUrl ─────────────────────
  WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
    log(buildEvent({
      metadata,
      action: "WebView.loadUrl",
      args: { url },
      suspicious: isSuspiciousUrl(url),
      context: { stack: get_java_stack() }
    }));
    return this.loadUrl(url);
  };

  // ─── WebView.loadData ─────────────────────
  WebView.loadData.overload(
    "java.lang.String", "java.lang.String", "java.lang.String"
  ).implementation = function (data, mime, encoding) {
    log(buildEvent({
      metadata,
      action: "WebView.loadData",
      args: {
        mime,
        encoding,
        data_preview: data?.slice?.(0, 200)
      },
      context: { stack: get_java_stack() }
    }));
    return this.loadData(data, mime, encoding);
  };

  // ─── WebView.loadDataWithBaseURL ──────────
  WebView.loadDataWithBaseURL.overload(
    "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String"
  ).implementation = function (baseUrl, data, mime, encoding, historyUrl) {
    log(buildEvent({
      metadata,
      action: "WebView.loadDataWithBaseURL",
      args: {
        base_url: baseUrl,
        mime,
        encoding,
        history_url: historyUrl,
        data_preview: data?.slice?.(0, 200)
      },
      context: { stack: get_java_stack() }
    }));
    return this.loadDataWithBaseURL(baseUrl, data, mime, encoding, historyUrl);
  };

  // ─── WebView.evaluateJavascript ────────────
  if (WebView.evaluateJavascript) {
    WebView.evaluateJavascript.overload(
      "java.lang.String", "android.webkit.ValueCallback"
    ).implementation = function (script, callback) {
      log(buildEvent({
        metadata,
        action: "WebView.evaluateJavascript",
        args: {
          script_preview: script?.slice?.(0, 300)
        },
        suspicious: true,
        context: { stack: get_java_stack() }
      }));
      return this.evaluateJavascript(script, callback);
    };
  }

  // ─── WebView.addJavascriptInterface ────────
  WebView.addJavascriptInterface.overload(
    "java.lang.Object", "java.lang.String"
  ).implementation = function (obj, name) {
    log(buildEvent({
      metadata,
      action: "WebView.addJavascriptInterface",
      args: {
        interface_name: name,
        object_class: obj?.$className || "<unknown>"
      },
      suspicious: true,
      context: { stack: get_java_stack() }
    }));
    return this.addJavascriptInterface(obj, name);
  };

  // ─── Hook WebViewClient.shouldOverrideUrlLoading ───
  try {
    const WebViewClient = Java.use("android.webkit.WebViewClient");

    WebViewClient.shouldOverrideUrlLoading.overload(
      "android.webkit.WebView", "java.lang.String"
    ).implementation = function (view, url) {
      log(buildEvent({
        metadata,
        action: "WebViewClient.shouldOverrideUrlLoading (String)",
        args: { url },
        suspicious: isSuspiciousUrl(url),
        context: { stack: get_java_stack() }
      }));
      return this.shouldOverrideUrlLoading(view, url);
    };

    WebViewClient.shouldOverrideUrlLoading.overload(
      "android.webkit.WebView", "android.webkit.WebResourceRequest"
    ).implementation = function (view, request) {
      const url = request?.getUrl?.()?.toString?.() || "<unknown>";
      log(buildEvent({
        metadata,
        action: "WebViewClient.shouldOverrideUrlLoading (Request)",
        args: { url },
        suspicious: isSuspiciousUrl(url),
        context: { stack: get_java_stack() }
      }));
      return this.shouldOverrideUrlLoading(view, request);
    };

  } catch (e) {
    console.warn(`[${metadata.name}] WebViewClient hooks failed: ${e.message}`);
  }

  log(buildEvent({ metadata, action: "hook_loaded" }));
  send({ type: "hook_loaded", hook: metadata.name, java: false });
  console.log(`[+] ${metadata.name} initialized`);
}, {
  name: "hook_webview",
  entrypoint: "java"
});
