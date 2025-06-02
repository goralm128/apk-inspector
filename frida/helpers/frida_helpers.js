'use strict';

/**
 * Exports createHookLogger and helper utilities to globalThis
 */

globalThis.createHookLogger = function ({ hook, category, tags = [], description = "", sensitive = false }) {
    const metadata = { name: hook, category, tags, description, sensitive };
    return function logEvent(eventPayload) {
        const event = {
            ...eventPayload,
            hook,
            metadata,
            timestamp: new Date().toISOString(),
            threadId: Process.getCurrentThreadId()
        };
        send(event);
    };
};

/**
 * Utility: Safe Frida send wrapper
 */
globalThis.send_event = function (data, context = {}) {
    try {
        const payload = {
            ...context,
            ...data,
            timestamp: new Date().toISOString(),
        };
        send(payload);
    } catch (e) {
        send({
            type: "internal_error",
            message: "send_event failed",
            error: e.toString()
        });
    }
};

/**
 * Convert a byte array to hex string
 */
globalThis.toHex = function (array) {
    return Array.prototype.map.call(array, x => ('00' + x.toString(16)).slice(-2)).join('');
};

/**
 * Safely get a Java stack trace (Android only)
 */
globalThis.get_java_stack = function () {
    try {
        return Java.use("java.lang.Exception").$new().getStackTrace()
            .map(frame => frame.toString())
            .join('\n');
    } catch (_) {
        return "N/A (no Java context)";
    }
};

/**
 * Try to get current thread's name (Android only)
 */
globalThis.get_thread_name = function () {
    try {
        return Java.use("java.lang.Thread").currentThread().getName();
    } catch (_) {
        return "unknown-thread";
    }
};

globalThis.isSensitiveNativeFunction = function (name) {
    const risky = ["system", "exec", "dlopen", "fork", "popen", "CreateProcess"];
    return risky.includes(name.toLowerCase());
};
