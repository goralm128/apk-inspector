'use strict';

const metadata = {
    name: "hook_cryptor",
    category: "crypto_usage",
    description: "Intercepts crypto-related Java APIs",
    tags: ["crypto", "java", "cipher"],
    sensitive: true
};

runWhenJavaIsReady(() => {
    waitForLogger(metadata, (log) => {
        try {
            const C = Java.use("javax.crypto.Cipher");
            C.getInstance.overload("java.lang.String").implementation = function (algo) {
                log({ hook: metadata.name, action: "getInstance", algorithm: algo });
                return this.getInstance(algo);
            };
        } catch (e) {
            console.error(`[${metadata.name}] Hook failed: ${e}`);
        }

        send({ type: 'hook_loaded', hook: metadata.name, java: true });
        console.log(`[+] ${metadata.name} initialized`);
    });
});
