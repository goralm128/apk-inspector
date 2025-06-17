'use strict';

(async function () {
  const metadata = {
    name: "hook_crypto",
    category: "crypto_usage",
    description: "Monitors Java crypto API usage",
    tags: ["crypto", "java", "cipher"],
    sensitive: true,
    entrypoint: "java"
  };

  try {
    await runWhenJavaIsReady();
    const log = await waitForLogger(metadata);
    console.log("[hook_crypto] Java VM ready, installing crypto hooks...");

    const Cipher = Java.use("javax.crypto.Cipher");

    Cipher.getInstance.overload("java.lang.String").implementation = function (algorithm) {
      const algoStr = algorithm?.toString?.() || "null";

      log({
        action: "Cipher.getInstance",
        algorithm: algoStr,
        thread: get_thread_name(),
        stack: get_java_stack()
      });

      console.log(`[hook_crypto] Cipher.getInstance("${algoStr}")`);
      return this.getInstance(algorithm);
    };

    console.log("[hook_crypto] Cipher.getInstance hook installed");

    send({
      type: 'hook_loaded',
      hook: metadata.name,
      java: true
    });
    console.log(`[+] ${metadata.name} initialized`);

  } catch (e) {
    console.error(`[hook_crypto] Initialization failed: ${e}`);
  }
})();
