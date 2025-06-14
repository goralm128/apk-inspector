'use strict';

const metadata = {
    name: "hook_accessibility_service",
    category: "accessibility_abuse",
    description: "Monitors usage of AccessibilityService API",
    tags: ["accessibility", "uiautomation", "abuse"],
    sensitive: true
};

runWhenJavaIsReady(() => {
    waitForLogger(metadata, (log) => {
        try {
            const A = Java.use("android.accessibilityservice.AccessibilityService");
            A.onServiceConnected.overload().implementation = function () {
                try {
                    log({ hook: metadata.name, action: "onServiceConnected", component: this.getComponentName().toString() });
                } catch (e) {
                    console.error(`[${metadata.name}] log() failed: ${e}`);
                }
                return this.onServiceConnected();
            };
        } catch (e) {
            console.error(`[${metadata.name}] Hook failed: ${e}`);
        }

        try {
            const N = Java.use("android.view.accessibility.AccessibilityNodeInfo");
            N.performAction.overload('int').implementation = function (actionId) {
                try {
                    log({ hook: metadata.name, action: "performAction", action_id: actionId, node: this.toString() });
                } catch (e) {
                    console.error(`[${metadata.name}] log() failed: ${e}`);
                }
                return this.performAction(actionId);
            };
        } catch (e) {
            console.error(`[${metadata.name}] Hook failed: ${e}`);
        }

        send({ type: 'hook_loaded', hook: metadata.name, java: true });
        console.log(`[+] ${metadata.name} initialized`);
    });
});
