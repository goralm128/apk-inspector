'use strict';

Java.perform(function () {
    const NetworkHooks = [];

    function log(event) {
        event.timestamp = new Date().toISOString();
        send(event);
    }

    // --- java.net.URL + HttpURLConnection ---
    try {
        const URL = Java.use('java.net.URL');

        URL.openConnection.overload().implementation = function () {
            const conn = this.openConnection();
            log({
                event: "openConnection",
                url: this.toString(),
                class: conn.getClass().getName()
            });
            return conn;
        };

        URL.openConnection.overload('java.net.Proxy').implementation = function (proxy) {
            const conn = this.openConnection(proxy);
            log({
                event: "openConnectionWithProxy",
                url: this.toString(),
                proxy: proxy.toString(),
                class: conn.getClass().getName()
            });
            return conn;
        };

        NetworkHooks.push('java.net.URL.openConnection');
    } catch (e) {
        log({ event: "warn", where: "java.net.URL", error: e.message });
    }

    // --- javax.net.ssl.HttpsURLConnection ---
    try {
        const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');

        HttpsURLConnection.connect.implementation = function () {
            log({ event: "HttpsURLConnection.connect", url: this.getURL().toString() });
            return this.connect();
        };

        HttpsURLConnection.getInputStream.implementation = function () {
            log({ event: "HttpsURLConnection.getInputStream", url: this.getURL().toString() });
            return this.getInputStream();
        };

        HttpsURLConnection.getOutputStream.implementation = function () {
            log({ event: "HttpsURLConnection.getOutputStream", url: this.getURL().toString() });
            return this.getOutputStream();
        };

        NetworkHooks.push("javax.net.ssl.HttpsURLConnection.connect");
        NetworkHooks.push("javax.net.ssl.HttpsURLConnection.getInputStream");
        NetworkHooks.push("javax.net.ssl.HttpsURLConnection.getOutputStream");
    } catch (e) {
        log({ event: "warn", where: "HttpsURLConnection", error: e.message });
    }

    // --- OkHttp3 (optional) ---
    try {
        const RealCall = Java.use("okhttp3.RealCall");

        RealCall.execute.implementation = function () {
            const request = this.request();
            log({
                event: "okhttp_execute",
                method: request.method(),
                url: request.url().toString(),
                headers: request.headers().toString()
            });
            return this.execute();
        };

        NetworkHooks.push("okhttp3.RealCall.execute");
    } catch (e) {
        log({ event: "warn", where: "okhttp3", error: e.message });
    }

    // --- Retrofit support ---
    try {
        const RetrofitCall = Java.use("retrofit2.OkHttpCall");

        RetrofitCall.execute.implementation = function () {
            log({ event: "retrofit.execute", request: this.request().toString() });
            return this.execute();
        };

        NetworkHooks.push("retrofit2.OkHttpCall.execute");
    } catch (e) {
        log({ event: "warn", where: "retrofit2", error: e.message });
    }

    // --- Volley support ---
    try {
        const RequestQueue = Java.use("com.android.volley.RequestQueue");

        RequestQueue.add.overload("com.android.volley.Request").implementation = function (req) {
            log({
                event: "volley.add",
                url: req.getUrl(),
                method: req.getMethod()
            });
            return this.add(req);
        };

        NetworkHooks.push("com.android.volley.RequestQueue.add");
    } catch (e) {
        log({ event: "warn", where: "volley", error: e.message });
    }

    // --- Apache HttpClient ---
    try {
        const ApacheClient = Java.use("org.apache.http.impl.client.DefaultHttpClient");

        ApacheClient.execute.overload('org.apache.http.client.methods.HttpUriRequest').implementation = function (request) {
            log({
                event: "apache_http_execute",
                method: request.getMethod(),
                uri: request.getURI().toString()
            });
            return this.execute(request);
        };

        NetworkHooks.push("apache.httpclient.DefaultHttpClient.execute");
    } catch (e) {
        log({ event: "warn", where: "apache_httpclient", error: e.message });
    }

    // --- Fallback InputStream.read() ---
    try {
        const InputStream = Java.use("java.io.InputStream");

        InputStream.read.overload().implementation = function () {
            const result = this.read();
            log({ event: "InputStream.read", result });
            return result;
        };

        InputStream.read.overload('[B').implementation = function (b) {
            const result = this.read(b);
            log({ event: "InputStream.read(byte[])", result });
            return result;
        };

        NetworkHooks.push("java.io.InputStream.read");
    } catch (e) {
        log({ event: "warn", where: "InputStream.read", error: e.message });
    }

    // --- WebView: loadUrl ---
    try {
        const WebView = Java.use("android.webkit.WebView");

        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            log({ event: "WebView.loadUrl", url });
            return this.loadUrl(url);
        };

        NetworkHooks.push("android.webkit.WebView.loadUrl");
    } catch (e) {
        log({ event: "warn", where: "WebView.loadUrl", error: e.message });
    }

    // --- WebView: addJavascriptInterface ---
    try {
        const WebView = Java.use("android.webkit.WebView");

        WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String').implementation = function (obj, name) {
            log({
                event: "WebView.addJavascriptInterface",
                interfaceName: name,
                class: obj.getClass().getName()
            });
            return this.addJavascriptInterface(obj, name);
        };

        NetworkHooks.push("android.webkit.WebView.addJavascriptInterface");
    } catch (e) {
        log({ event: "warn", where: "WebView.addJavascriptInterface", error: e.message });
    }

    // --- Completion ---
    log({ event: "Java network hooks loaded", hooks: NetworkHooks });
});
