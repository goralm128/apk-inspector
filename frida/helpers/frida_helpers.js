'use strict';

(function () {
    // Helper: Check Java availability
    if (typeof globalThis.isJavaAvailable !== 'function') {
        globalThis.isJavaAvailable = function () {
            try {
                return typeof Java !== 'undefined' && Java.available;
            } catch (_) {
                return false;
            }
        };
    }

    // Helper: Wait for logger to be ready
    globalThis.waitForLogger = function waitForLogger(metadata, timeout = 5000, interval = 100) {
        return new Promise((resolve, reject) => {
            const start = Date.now();

            const check = () => {
            if (typeof globalThis.createHookLogger === 'function') {
                console.log(`[waitForLogger] Logger ready for ${metadata.name}`);
                const logger = createHookLogger(metadata);
                resolve(logger);
            } else if (Date.now() - start < timeout) {
                setTimeout(check, interval);
            } else {
                const msg = `[waitForLogger] Timeout waiting for createHookLogger (${metadata.name})`;
                console.error(msg);
                reject(new Error(msg));
            }
            };

            check();
        });
    };

    // Helper: Create structured hook logger
    if (typeof globalThis.createHookLogger !== 'function') {
        globalThis.createHookLogger = function ({
            hook,
            category,
            tags = [],
            description = "",
            sensitive = false
        }) {
            const metadata = { name: hook, category, tags, description, sensitive };

            return function logEvent(payload) {
                try {
                    const event = {
                        ...payload,
                        hook: metadata.name,
                        metadata,
                        timestamp: new Date().toISOString(),
                        threadId: Process.getCurrentThreadId()
                    };
                    if (!payload.hook) payload.hook = metadata.name;
                    send(event);
                } catch (e) {
                    console.error(`[createHookLogger] Failed for ${hook}: ${e}`);
                }
            };
        };
    }

    // Helper: Send custom event
    if (typeof globalThis.send_event !== 'function') {
        globalThis.send_event = function (data, context = {}) {
            try {
                const payload = {
                    ...data,
                    ...context,
                    timestamp: new Date().toISOString()
                };
                send(payload);
            } catch (e) {
                console.error(`[send_event] Failed: ${e}`);
            }
        };
    }

    // Helper: Convert byte array to hex
    if (typeof globalThis.toHex !== 'function') {
        globalThis.toHex = function (array) {
            if (!array || typeof array !== 'object' || !('length' in array)) return '';
            return Array.prototype.map.call(array, x => ('00' + x.toString(16)).slice(-2)).join('');
        };
    }

    // Java thread name
    if (typeof globalThis.get_thread_name !== 'function') {
        globalThis.get_thread_name = function () {
            if (!isJavaAvailable()) return "Java not available";
            try {
                return Java.use("java.lang.Thread").currentThread().getName();
            } catch (_) {
                return "unknown-thread";
            }
        };
    }

    // Java stack trace
    if (typeof globalThis.get_java_stack !== 'function') {
        globalThis.get_java_stack = function () {
            if (!isJavaAvailable()) return "Java not available";
            try {
                return Java.use("java.lang.Exception").$new().getStackTrace()
                    .map(frame => frame.toString())
                    .join('\n');
            } catch (_) {
                return "N/A";
            }
        };
    }

    // Delay Java code until VM is ready
    if (typeof globalThis.runWhenJavaIsReady !== 'function') {
        globalThis.runWhenJavaIsReady = function (callback, retryInterval = 500, maxRetries = 50) {
            let tries = 0;
            function attempt() {
                if (isJavaAvailable()) {
                    try {
                        Java.perform(callback);
                    } catch (e) {
                        console.error("[runWhenJavaIsReady] Java.perform failed:", e);
                    }
                } else if (tries < maxRetries) {
                    tries++;
                    setTimeout(attempt, retryInterval);
                } else {
                    console.error("[runWhenJavaIsReady] Java VM not available");
                }
            }
            attempt();
        };
    }

    // Identify risky functions
    if (typeof globalThis.isSensitiveNativeFunction !== 'function') {
        globalThis.isSensitiveNativeFunction = function (name) {
            if (typeof name !== 'string') return false;
            const risky = ["system", "exec", "dlopen", "fork", "popen", "CreateProcess"];
            return risky.includes(name.toLowerCase());
        };
    }

    globalThis.safeAttach = function safeAttach(
        funcName,
        callbacks,
        moduleName = null,
        {
            initialDelay = 0,
            maxRetries = 10,
            retryInterval = 200,
            verbose = true
        } = {}
        ) {
        return new Promise((resolve, reject) => {
            let attempts = 0;

            const tryHook = () => {
            let addr = null;
            try {
                addr = Module.findExportByName(moduleName, funcName);
            } catch (e) {
                return retry(`[safeAttach] Module lookup failed for ${funcName}: ${e}`);
            }

            if (!addr) {
                return retry(`[safeAttach] ${funcName} not found in ${moduleName || "default module"}`);
            }

            if (typeof Interceptor?.attach !== 'function') {
                return retry(`[safeAttach] Interceptor.attach not available`);
            }

            try {
                Interceptor.attach(addr, callbacks);
                if (verbose) console.log(`[safeAttach] Hooked ${funcName} at ${addr}`);
                resolve(addr);
            } catch (e) {
                reject(`[safeAttach] Attaching to ${funcName} failed: ${e}`);
            }
            };

            const retry = (log) => {
            if (++attempts < maxRetries) {
                if (verbose) console.warn(`${log}, retrying (${attempts}/${maxRetries})`);
                setTimeout(tryHook, retryInterval);
            } else {
                const msg = `[safeAttach] Giving up on ${funcName} after ${maxRetries} attempts`;
                console.error(msg);
                reject(msg);
            }
            };

            setTimeout(tryHook, initialDelay);
        });
    };


    // Notify host
 try {
    if (!globalThis._fridaHelpersInitialized) {
        globalThis._fridaHelpersInitialized = true;

        runWhenJavaIsReady(() => {
            send({
                type: 'frida_helpers_loaded',
                hook: "frida_helpers",
                category: 'system',
                tags: ["init"],
                timestamp: new Date().toISOString(),
                globals: {
                    runWhenJavaIsReady: typeof runWhenJavaIsReady === 'function',
                    createHookLogger: typeof createHookLogger === 'function',
                    isJavaAvailable: true  // We KNOW it's true here
                }
            });
        });
    }
} catch (e) {
    console.error("[frida_helpers] Initialization failed:", e);
}
})();
