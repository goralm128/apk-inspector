'use strict';

/**
 * Hook Metadata
 */
const metadata = {
    name: "hook_jni_trace",
    sensitive: false,
    tags: ["jni", "native"]
};

const logJni = createHookLogger({
    hook: "RegisterNatives",
    category: "native_injection",
    tags: metadata.tags,
    description: "Hooks RegisterNatives to monitor JNI",
    sensitive: metadata.sensitive
});

function tryAttachRegisterNatives() {
    const addr = Module.findExportByName(null, "RegisterNatives");
    if (!addr) return false;

    Interceptor.attach(addr, {
        onEnter(args) {
            const count = args[3].toInt32();
            for (let i = 0; i < count; i++) {
                const method = args[2].add(i * Process.pointerSize * 3);
                const name = method.readPointer().readCString();
                const sig = method.add(Process.pointerSize).readPointer().readCString();
                const fnPtr = method.add(Process.pointerSize * 2).readPointer();

                logJni({
                    action: "RegisterNatives",
                    name: name,
                    signature: sig,
                    pointer: fnPtr.toString()
                });
            }
        }
    });

    return true;
}

setTimeout(() => {
    if (!tryAttachRegisterNatives()) {
        setTimeout(() => {
            if (!tryAttachRegisterNatives()) {
                console.error("[!] Still couldn't find RegisterNatives.");
            }
        }, 2000);
    }
}, 2000);
