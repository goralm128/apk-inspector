'use strict';

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

runWhenJavaIsReady(async () => {
    try {
        const log = await waitForLogger(metadata);
        const HttpClient = Java.use("org.apache.http.impl.client.DefaultHttpClient");
        const HttpPost = Java.use("org.apache.http.client.methods.HttpPost");
        const HttpGet = Java.use("org.apache.http.client.methods.HttpGet");
        const URI = Java.use("java.net.URI");

        const clientExecute = HttpClient.execute.overload("org.apache.http.client.methods.HttpUriRequest");
        clientExecute.implementation = function (request) {
            let url = "<unknown>";
            let method = "<unknown>";
            let suspicious = false;

            try {
                method = request.getMethod();
                url = request.getURI().toString();
                suspicious = isSuspiciousUrl(url);
            } catch (_) {}

            log({
                action: "httpclient.execute",
                url,
                method,
                suspicious
            });

            return clientExecute.call(this, request);
        };

        const entityEnclosingRequestBase = Java.use("org.apache.http.client.methods.HttpEntityEnclosingRequestBase");
        const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
        entityEnclosingRequestBase.setEntity.implementation = function (entity) {
            try {
                const baos = ByteArrayOutputStream.$new();
                entity.writeTo(baos);
                const body = baos.toString();  // assumes UTF-8
                const suspicious = isSuspiciousUrl(body);
                log({
                    action: "httpclient.setEntity",
                    payload: body.slice(0, 300),
                    suspicious
                });
            } catch (e) {
                console.error(`[${metadata.name}] Entity capture failed: ${e}`);
            }
            return this.setEntity(entity);
        };

        send({ type: 'hook_loaded', hook: metadata.name, java: true });
        console.log(`[+] ${metadata.name} initialized`);
    } catch (e) {
        console.error(`[${metadata.name}] Initialization failed: ${e}`);
    }
});
