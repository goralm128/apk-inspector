'use strict';

Java.perform(function () {
    const NetworkHooks = [];

    // --- java.net.URL + HttpURLConnection ---
    try {
        const URL = Java.use('java.net.URL');

        URL.openConnection.overload().implementation = function () {
            const conn = this.openConnection();
            log({
                event: "openConnection",
                category: "network",
                source: "java.net.URL",
                url: this.toString(),
                class: conn.getClass().getName()
            });
            return conn;
        };

        URL.openConnection.overload('java.net.Proxy').implementation = function (proxy) {
            const conn = this.openConnection(proxy);
            log({
                event: "openConnectionWithProxy",
                category: "network",
                source: "java.net.URL",
                url: this.toString(),
                proxy: proxy.toString(),
                class: conn.getClass().getName()
            });
            return conn;
        };

        NetworkHooks.push('java.net.URL.openConnection');
    } catch (e) {
        log({ event: "warn", category: "network", source: "java.net.URL", error: e.message });
    }

    // --- javax.net.ssl.HttpsURLConnection ---
    try {
        const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');

        HttpsURLConnection.connect.implementation = function () {
            log({
                event: "HttpsURLConnection.connect",
                category: "network",
                source: "javax.net.ssl.HttpsURLConnection",
                url: this.getURL().toString()
            });
            return this.connect();
        };

        HttpsURLConnection.getInputStream.implementation = function () {
            log({
                event: "HttpsURLConnection.getInputStream",
                category: "network",
                source: "javax.net.ssl.HttpsURLConnection",
                url: this.getURL().toString()
            });
            return this.getInputStream();
        };

        HttpsURLConnection.getOutputStream.implementation = function () {
            log({
                event: "HttpsURLConnection.getOutputStream",
                category: "network",
                source: "javax.net.ssl.HttpsURLConnection",
                url: this.getURL().toString()
            });
            return this.getOutputStream();
        };

        NetworkHooks.push("javax.net.ssl.HttpsURLConnection");
    } catch (e) {
        log({ event: "warn", category: "network", source: "HttpsURLConnection", error: e.message });
    }

    // --- OkHttp3 ---
    try {
        const RealCall = Java.use("okhttp3.RealCall");

        RealCall.execute.implementation = function () {
            const request = this.request();
            log({
                event: "okhttp_execute",
                category: "network",
                source: "okhttp3.RealCall",
                method: request.method(),
                url: request.url().toString(),
                headers: request.headers().toString()
            });
            return this.execute();
        };

        NetworkHooks.push("okhttp3.RealCall.execute");
    } catch (e) {
        log({ event: "warn", category: "network", source: "okhttp3", error: e.message });
    }

    // --- Retrofit support ---
    try {
        const RetrofitCall = Java.use("retrofit2.OkHttpCall");

        RetrofitCall.execute.implementation = function () {
            log({
                event: "retrofit.execute",
                category: "network",
                source: "retrofit2.OkHttpCall",
                request: this.request().toString()
            });
            return this.execute();
        };

        NetworkHooks.push("retrofit2.OkHttpCall.execute");
    } catch (e) {
        log({ event: "warn", category: "network", source: "retrofit2", error: e.message });
    }

    // --- Volley support ---
    try {
        const RequestQueue = Java.use("com.android.volley.RequestQueue");

        RequestQueue.add.overload("com.android.volley.Request").implementation = function (req) {
            log({
                event: "volley.add",
                category: "network",
                source: "com.android.volley.RequestQueue",
                url: req.getUrl(),
                method: req.getMethod()
            });
            return this.add(req);
        };

        NetworkHooks.push("com.android.volley.RequestQueue.add");
    } catch (e) {
        log({ event: "warn", category: "network", source: "volley", error: e.message });
    }

    // --- Apache HttpClient ---
    try {
        const ApacheClient = Java.use("org.apache.http.impl.client.DefaultHttpClient");

        ApacheClient.execute.overload('org.apache.http.client.methods.HttpUriRequest').implementation = function (request) {
            log({
                event: "apache_http_execute",
                category: "network",
                source: "apache.httpclient.DefaultHttpClient",
                method: request.getMethod(),
                uri: request.getURI().toString()
            });
            return this.execute(request);
        };

        NetworkHooks.push("apache.httpclient.DefaultHttpClient.execute");
    } catch (e) {
        log({ event: "warn", category: "network", source: "apache_httpclient", error: e.message });
    }

    // --- InputStream.read ---
    try {
        const InputStream = Java.use("java.io.InputStream");

        InputStream.read.overload().implementation = function () {
            const result = this.read();
            log({
                event: "InputStream.read",
                category: "network",
                source: "java.io.InputStream",
                result
            });
            return result;
        };

        InputStream.read.overload('[B').implementation = function (b) {
            const result = this.read(b);
            log({
                event: "InputStream.read(byte[])",
                category: "network",
                source: "java.io.InputStream",
                result
            });
            return result;
        };

        NetworkHooks.push("java.io.InputStream.read");
    } catch (e) {
        log({ event: "warn", category: "network", source: "InputStream.read", error: e.message });
    }

    // --- WebView.loadUrl ---
    try {
        const WebView = Java.use("android.webkit.WebView");

        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            log({
                event: "WebView.loadUrl",
                category: "network",
                source: "android.webkit.WebView",
                url
            });
            return this.loadUrl(url);
        };

        NetworkHooks.push("android.webkit.WebView.loadUrl");
    } catch (e) {
        log({ event: "warn", category: "network", source: "WebView.loadUrl", error: e.message });
    }

    // --- WebView.addJavascriptInterface ---
    try {
        const WebView = Java.use("android.webkit.WebView");

        WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String').implementation = function (obj, name) {
            log({
                event: "WebView.addJavascriptInterface",
                category: "network",
                source: "android.webkit.WebView",
                interfaceName: name,
                class: obj.getClass().getName()
            });
            return this.addJavascriptInterface(obj, name);
        };

        NetworkHooks.push("android.webkit.WebView.addJavascriptInterface");
    } catch (e) {
        log({ event: "warn", category: "network", source: "WebView.addJavascriptInterface", error: e.message });
    }

    log({ event: "Java network hooks loaded", category: "system", source: "frida", hooks: NetworkHooks });
});
