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
    if (typeof globalThis.waitForLogger !== 'function') {
        globalThis.waitForLogger = function (metadata, callback, retries = 20, interval = 100) {
            let attempts = 0;
            const wait = () => {
                try {
                    if (typeof createHookLogger === 'function') {
                        const log = createHookLogger(metadata);
                        console.log(`[waitForLogger] Ready for: ${metadata.name}`);
                        callback(log);
                    } else if (++attempts < retries) {
                        setTimeout(wait, interval);
                    } else {
                        console.error(`[waitForLogger] createHookLogger not ready for ${metadata.name}`);
                    }
                } catch (e) {
                    console.error(`[waitForLogger] Failed for ${metadata.name}: ${e}`);
                }
            };
            wait();
        };
    }

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

    globalThis.safeAttach = function (
        funcName,
        callbacks,
        moduleName = null,
        {
            delay = 1000,
            maxRetries = 10,
            retryInterval = 300,
            verbose = true
        } = {}
        ) {
        let attempts = 0;

        const tryAttach = () => {
            try {
            const addr = Module.findExportByName(moduleName, funcName);
            if (!addr || addr.isNull()) {
                if (verbose) console.warn(`[safeAttach] ${funcName} not found.`);
                if (++attempts < maxRetries) setTimeout(tryAttach, retryInterval);
                return;
            }

            if (typeof Interceptor === 'undefined') {
                console.error("[frida_helpers] Interceptor not available yet");
            }

            if (typeof Interceptor?.attach !== 'function') {
                if (++attempts < maxRetries) {
                if (verbose) console.warn(`[safeAttach] Interceptor not ready for ${funcName}, retrying...`);
                setTimeout(tryAttach, retryInterval);
                }
                return;
            }

            Interceptor.attach(addr, callbacks);
            console.log(`[safeAttach] Hooked ${funcName} at ${addr}`);
            console.log(`[safeAttach] Hooked ${funcName} at ${addr}`);
            return; // Prevent retry after success

            } catch (ex) {
                console.error(`[safeAttach] Hooking ${funcName} failed:`, ex);
            }
        };

        setTimeout(tryAttach, delay);
    };

    // Notify host
    try {
        if (!globalThis._fridaHelpersInitialized) {
            globalThis._fridaHelpersInitialized = true;
            send({
                type: 'frida_helpers_loaded',
                hook: "frida_helpers",
                category: 'system',
                tags: ["init"],
                timestamp: new Date().toISOString(),
                globals: {
                    runWhenJavaIsReady: typeof runWhenJavaIsReady === 'function',
                    createHookLogger: typeof createHookLogger === 'function',
                    isJavaAvailable: isJavaAvailable(),
                }
            });
        }
    } catch (e) {
        console.error("[frida_helpers] Initialization failed:", e);
    }
})();
