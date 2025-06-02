'use strict';

/**
 * Hook Metadata
 */
const metadata = {
    name: "hook_open",
    sensitive: true,
    tags: ["native", "file", "fs"]
};

const logOpen = createHookLogger({
    hook: "open",
    category: "filesystem",
    tags: metadata.tags,
    description: "Hooks open() syscall",
    sensitive: metadata.sensitive
});

try {
    const openPtr = Module.getExportByName(null, "open");
    Interceptor.attach(openPtr, {
        onEnter(args) {
            this.path = Memory.readUtf8String(args[0]);
        },
        onLeave(retval) {
            if (this.path) {
                logOpen({
                    action: "open",
                    file_path: this.path,
                    retval: retval.toInt32()
                });
            }
        }
    });
} catch (e) {
    console.error("Failed to hook 'open':", e);
}
