'use strict';
/**
 * Hook Metadata
 */
const metadata = {
    name: "hook_cryptor",
    sensitive: true,
    tags: ["crypto", "java", "cipher"]
};

// Crypto hooks — Java side
Java.perform(() => {
    const logCipher = createHookLogger({
        hook: "Cipher.getInstance",
        category: "crypto_usage",
        tags: metadata.tags,
        description: "Hooks Cipher.getInstance()",
        sensitive: metadata.sensitive
    });

    const Cipher = Java.use("javax.crypto.Cipher");

    Cipher.getInstance.overload("java.lang.String").implementation = function (algo) {
        logCipher({
            action: "getInstance",
            algorithm: algo
        });
        return this.getInstance(algo);
    };
});
