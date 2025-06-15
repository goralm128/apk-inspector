'use strict';

const metadata = {
    name: "hook_cryptor",
    category: "crypto_usage",
    description: "Intercepts crypto-related Java APIs",
    tags: ["crypto", "java", "cipher"],
    sensitive: true
};

runWhenJavaIsReady(async () => {
    try {
        const log = await waitForLogger(metadata);
        const C = Java.use("javax.crypto.Cipher");
        const getInstanceStr = C.getInstance.overload("java.lang.String");

        getInstanceStr.implementation = function (algo) {
            log({ action: "getInstance", algorithm: algo });
            return getInstanceStr.call(this, algo);
        };

        send({ type: 'hook_loaded', hook: metadata.name, java: true });
        console.log(`[+] ${metadata.name} initialized`);
    } catch (e) {
        console.error(`[${metadata.name}] Initialization failed: ${e}`);
    }
});
