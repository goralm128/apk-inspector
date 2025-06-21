'use strict';

maybeRunJavaHook(async () => {
  const metadata = {
    name: "hook_java_root_check",
    category: "evasion",
    description: "Fakes responses to Java-based root detection techniques",
    tags: ["java", "root", "evasion", "frida"],
    sensitive: true,
    entrypoint: "java"
  };

  const log = createHookLogger(metadata);

  function isSuspiciousPath(path) {
    return path && path.match(/\/(su|magisk|busybox|superuser|data\/local\/tmp|xposed|zygisk|frida|rootcloak)/i);
  }

  function isSuspiciousCmd(cmd) {
    return cmd && cmd.match(/\b(su|getprop|whoami|busybox|which|magisk|xposed|mount|id|grep|tr)\b/i);
  }

  function fakeExecResult() {
    const ProcessBuilder = Java.use("java.lang.ProcessBuilder");
    return ProcessBuilder.$new(["echo", ""]).start();
  }

  function logFake(action, args = {}) {
    log(buildEvent({
      metadata,
      action,
      args,
      suspicious: true,
      error: false
    }));
  }

  // ─── File.exists / canExecute ───
  const File = Java.use("java.io.File");

  File.exists.implementation = function () {
    const path = this.getAbsolutePath();
    if (isSuspiciousPath(path)) {
      logFake("faked_File.exists", { path });
      return false;
    }
    return this.exists();
  };

  File.canExecute.implementation = function () {
    const path = this.getAbsolutePath();
    if (isSuspiciousPath(path)) {
      logFake("faked_File.canExecute", { path });
      return false;
    }
    return this.canExecute();
  };

  // ─── Runtime.exec ───
  const Runtime = Java.use("java.lang.Runtime");

  Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
    if (isSuspiciousCmd(cmd)) {
      logFake("faked_Runtime.exec", { cmd });
      return fakeExecResult();
    }
    return this.exec(cmd);
  };

  Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArray) {
    const cmd = cmdArray.join(" ");
    if (isSuspiciousCmd(cmd)) {
      logFake("faked_Runtime.exec_array", { cmd });
      return fakeExecResult();
    }
    return this.exec(cmdArray);
  };

  // ─── BufferedReader.readLine ───
  const BufferedReader = Java.use("java.io.BufferedReader");
  BufferedReader.readLine.implementation = function () {
    const line = this.readLine();
    if (line && isSuspiciousPath(line)) {
      logFake("faked_BufferedReader.readLine", { line });
      return "";
    }
    return line;
  };

  // ─── System.getenv ───
  const System = Java.use("java.lang.System");
  System.getenv.overload().implementation = function () {
    const env = this.getenv();
    const fakeKeys = ["PATH", "LD_LIBRARY_PATH", "ANDROID_ROOT"];
    for (const key of fakeKeys) {
      if (env.containsKey(key)) {
        const val = env.get(key);
        if (isSuspiciousPath(val)) {
          logFake("faked_System.getenv", { key, original: val });
          env.put(key, "/system/bin");
        }
      }
    }
    return env;
  };

  // ─── Build.TAGS / FINGERPRINT / HOST ───
  const Build = Java.use("android.os.Build");

  Build.TAGS.value = "release-keys";
  Build.FINGERPRINT.value = "google/sdk_gphone64/emu64:12/SE1A.220829.007/8856816:user/release-keys";
  Build.HOST.value = "release-host";

  logFake("faked_Build_constants", {
    TAGS: Build.TAGS.value,
    FINGERPRINT: Build.FINGERPRINT.value,
    HOST: Build.HOST.value
  });

  // ─── System.exit / Runtime.exit ───
  System.exit.implementation = function (code) {
    logFake("faked_System.exit", { code });
  };

  Runtime.exit.implementation = function (code) {
    logFake("faked_Runtime.exit", { code });
  };

  log(buildEvent({ metadata, action: "hook_loaded", args: {} }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized with fake-only behavior`);
}, {
  name: "hook_java_root_check",
  entrypoint: "java"
});
