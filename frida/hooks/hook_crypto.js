'use strict';

maybeRunJavaHook(async () => {
  const metadata = {
    name: "hook_crypto",
    category: "crypto_usage",
    description: "Monitors Java crypto API usage",
    tags: ["crypto", "java", "cipher", "digest", "mac", "keygen"],
    sensitive: true,
    entrypoint: "java"
  };

  const log = await waitForLogger(metadata);
  console.log(`[${metadata.name}] Java VM ready, installing crypto hooks...`);

  const Cipher = Java.use("javax.crypto.Cipher");

  Cipher.getInstance.overload("java.lang.String").implementation = function (algorithm) {
    log(buildEvent({
      metadata,
      action: "Cipher.getInstance",
      args: { algorithm },
      context: { stack: get_java_stack() }
    }));
    return this.getInstance(algorithm);
  };
  console.log(`[${metadata.name}] Hooked Cipher.getInstance`);

  Cipher.doFinal.overload("[B").implementation = function (input) {
    log(buildEvent({
      metadata,
      action: "Cipher.doFinal",
      args: { input_length: input.length },
      context: { stack: get_java_stack() }
    }));
    return this.doFinal(input);
  };
  console.log(`[${metadata.name}] Hooked Cipher.doFinal`);

  const MessageDigest = Java.use("java.security.MessageDigest");

  MessageDigest.getInstance.overload("java.lang.String").implementation = function (algo) {
    log(buildEvent({
      metadata,
      action: "MessageDigest.getInstance",
      args: { algorithm: algo },
      context: { stack: get_java_stack() }
    }));
    return this.getInstance(algo);
  };
  console.log(`[${metadata.name}] Hooked MessageDigest.getInstance`);

  const Mac = Java.use("javax.crypto.Mac");

  Mac.getInstance.overload("java.lang.String").implementation = function (algo) {
    log(buildEvent({
      metadata,
      action: "Mac.getInstance",
      args: { algorithm: algo },
      context: { stack: get_java_stack() }
    }));
    return this.getInstance(algo);
  };
  console.log(`[${metadata.name}] Hooked Mac.getInstance`);

  const KeyGenerator = Java.use("javax.crypto.KeyGenerator");

  KeyGenerator.getInstance.overload("java.lang.String").implementation = function (algo) {
    log(buildEvent({
      metadata,
      action: "KeyGenerator.getInstance",
      args: { algorithm: algo },
      context: { stack: get_java_stack() }
    }));
    return this.getInstance(algo);
  };
  console.log(`[${metadata.name}] Hooked KeyGenerator.getInstance`);

  log(buildEvent({ metadata, action: "hook_loaded" }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized`);
}, {
  name: "hook_crypto",
  entrypoint: "java"
});
