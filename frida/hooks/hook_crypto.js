'use strict';

(async function () {
  const metadata = {
    name: "hook_crypto",
    category: "crypto_usage",
    description: "Monitors Java crypto API usage",
    tags: ["crypto", "java", "cipher", "digest", "mac", "keygen"],
    sensitive: true,
    entrypoint: "java"
  };

  try {
    await runWhenJavaIsReady();
    const log = await waitForLogger(metadata);
    console.log("[hook_crypto] Java VM ready, installing crypto hooks...");

    const Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload("java.lang.String").implementation = function (algorithm) {
      log({
        action: "Cipher.getInstance",
        algorithm,
        thread: get_thread_name(),
        stack: get_java_stack()
      });
      return this.getInstance(algorithm);
    };
    console.log("[hook_crypto] Hooked Cipher.getInstance");

    Cipher.doFinal.overload("[B").implementation = function (input) {
      log({
        action: "Cipher.doFinal",
        input_length: input.length,
        thread: get_thread_name(),
        stack: get_java_stack()
      });
      return this.doFinal(input);
    };
    console.log("[hook_crypto] Hooked Cipher.doFinal");

    const MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.getInstance.overload("java.lang.String").implementation = function (algo) {
      log({
        action: "MessageDigest.getInstance",
        algorithm: algo,
        thread: get_thread_name(),
        stack: get_java_stack()
      });
      return this.getInstance(algo);
    };
    console.log("[hook_crypto] Hooked MessageDigest.getInstance");

    const Mac = Java.use("javax.crypto.Mac");
    Mac.getInstance.overload("java.lang.String").implementation = function (algo) {
      log({
        action: "Mac.getInstance",
        algorithm: algo,
        thread: get_thread_name(),
        stack: get_java_stack()
      });
      return this.getInstance(algo);
    };
    console.log("[hook_crypto] Hooked Mac.getInstance");

    const KeyGenerator = Java.use("javax.crypto.KeyGenerator");
    KeyGenerator.getInstance.overload("java.lang.String").implementation = function (algo) {
      log({
        action: "KeyGenerator.getInstance",
        algorithm: algo,
        thread: get_thread_name(),
        stack: get_java_stack()
      });
      return this.getInstance(algo);
    };
    console.log("[hook_crypto] Hooked KeyGenerator.getInstance");

    send({ type: 'hook_loaded', hook: metadata.name, java: true });
    console.log(`[+] ${metadata.name} initialized`);

  } catch (e) {
    console.error(`[hook_crypto] Initialization failed: ${e}`);
  }
})();
