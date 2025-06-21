'use strict';

maybeRunJavaHook(async () => {
  const metadata = {
    name: "hook_retrofit",
    category: "network",
    description: "Intercepts Retrofit requests and responses (sync, async, coroutine)",
    tags: ["java", "retrofit", "okhttp", "network", "http", "coroutine"],
    sensitive: true,
    entrypoint: "java"
  };

  const log = await waitForLogger(metadata);

  Java.perform(() => {
    const URL = req => req?.url?.().toString?.() || "<unknown>";
    const METHOD = req => req?.method?.() || "<unknown>";
    const HEADERS = req => req?.headers?.().toString?.() || "<none>";

    const getBodySafe = (resp) => {
      try {
        const body = resp?.body?.()?.string?.();
        return body?.slice?.(0, 512) || "<empty>";
      } catch (e) {
        return `<error: ${e}>`;
      }
    };

    // --- Retrofit2.OkHttpCall (sync/async) ---
    Java.enumerateLoadedClasses({
      onMatch(name) {
        if (name === "retrofit2.OkHttpCall") {
          try {
            const OkHttpCall = Java.use("retrofit2.OkHttpCall");

            OkHttpCall.execute.implementation = function () {
              const request = this.request();
              const url = URL(request);
              const method = METHOD(request);
              const headers = HEADERS(request);

              log(buildEvent({
                metadata,
                action: "Retrofit.execute",
                args: { url, method, headers },
                context: { stack: get_java_stack() }
              }));

              const response = this.execute();

              log(buildEvent({
                metadata,
                action: "Retrofit.response.sync",
                args: { url, body: getBodySafe(response) }
              }));

              return response;
            };

            OkHttpCall.enqueue.implementation = function (callback) {
              const request = this.request();
              const url = URL(request);
              const method = METHOD(request);
              const headers = HEADERS(request);

              log(buildEvent({
                metadata,
                action: "Retrofit.enqueue",
                args: { url, method, headers },
                context: { stack: get_java_stack() }
              }));

              const Wrapper = Java.registerClass({
                name: 'com.frida.HookedRetrofitCallback',
                implements: [Java.use("retrofit2.Callback")],
                methods: {
                  onResponse: {
                    returnType: 'void',
                    argumentTypes: ['retrofit2.Call', 'retrofit2.Response'],
                    implementation: function (call, response) {
                      log(buildEvent({
                        metadata,
                        action: "Retrofit.response.async",
                        args: { url, body: getBodySafe(response) }
                      }));
                      return callback.onResponse(call, response);
                    }
                  },
                  onFailure: {
                    returnType: 'void',
                    argumentTypes: ['retrofit2.Call', 'java.lang.Throwable'],
                    implementation: function (call, throwable) {
                      log(buildEvent({
                        metadata,
                        action: "Retrofit.response.failure",
                        args: {
                          url,
                          error: throwable?.toString?.() || "<unknown>"
                        },
                        error: true
                      }));
                      return callback.onFailure(call, throwable);
                    }
                  }
                }
              });

              return this.enqueue(Wrapper.$new());
            };

            console.log(`[${metadata.name}] Hooked OkHttpCall.execute and enqueue`);
          } catch (e) {
            console.error(`[${metadata.name}] Failed hooking OkHttpCall: ${e}`);
          }
        }

        // --- Coroutine Support ---
        if (name.includes("retrofit2.KotlinExtensions") && name.endsWith("await")) {
          try {
            const cls = Java.use(name);
            const methods = cls.class.getDeclaredMethods();

            methods.forEach(method => {
              if (method.getName().includes("await")) {
                try {
                  method.setAccessible(true);
                  const overloads = cls[method.getName()].overloads;

                  overloads.forEach(overload => {
                    overload.implementation = function () {
                      const url = this?.request?.()?.url?.().toString?.() || "<unknown>";

                      log(buildEvent({
                        metadata,
                        action: `Retrofit.await (${method.getName()})`,
                        args: { url },
                        context: { stack: get_java_stack() }
                      }));

                      return overload.apply(this, arguments);
                    };
                  });

                  console.log(`[${metadata.name}] Hooked coroutine ${name}.${method.getName()}`);
                } catch (e) {
                  console.error(`[${metadata.name}] Coroutine hook error (${method.getName()}): ${e}`);
                }
              }
            });
          } catch (_) {
            // Non-Kotlin apps silently skip
          }
        }
      },
      onComplete() {}
    });

    log(buildEvent({ metadata, action: "hook_loaded" }));
    send({ type: 'hook_loaded', hook: metadata.name });
    console.log(`[+] ${metadata.name} initialized`);
  });
}, {
  name: "hook_retrofit",
  entrypoint: "java"
});
