'use strict';

const metadata = {
    name: "hook_accessibility_service",
    category: "accessibility_abuse",
    description: "Monitors usage of AccessibilityService API",
    tags: ["accessibility", "uiautomation", "abuse"],
    sensitive: true
};

runWhenJavaIsReady(async () => {
    try {
        const log = await waitForLogger(metadata);

        const A = Java.use("android.accessibilityservice.AccessibilityService");
        const original_onServiceConnected = A.onServiceConnected;

        A.onServiceConnected.implementation = function () {
            try {
                log({ action: "onServiceConnected", component: this.getComponentName().toString() });
            } catch (e) {
                console.error(`[${metadata.name}] log failed: ${e}`);
            }
            return original_onServiceConnected.call(this);
        };

        const N = Java.use("android.view.accessibility.AccessibilityNodeInfo");
        const original_performAction = N.performAction.overload('int');

        original_performAction.implementation = function (actionId) {
            try {
                log({
                    action: "performAction",
                    action_id: actionId,
                    node: this.toString()
                });
            } catch (e) {
                console.error(`[${metadata.name}] log failed: ${e}`);
            }
            return original_performAction.call(this, actionId);
        };

        const AE = Java.use("android.view.accessibility.AccessibilityEvent");
        const original_sendEvent = A.sendAccessibilityEvent;

        A.sendAccessibilityEvent.implementation = function (event) {
            try {
                const type = event.getEventType();
                const pkg = event.getPackageName()?.toString() || "unknown";
                const cls = event.getClassName()?.toString() || "unknown";
                const desc = event.getContentDescription()?.toString() || "none";
                const txt = event.getText()?.toArray().join(" ") || "none";

                log({
                    action: "sendAccessibilityEvent",
                    type,
                    package: pkg,
                    class: cls,
                    description: desc,
                    text: txt,
                    time: event.getEventTime()
                });
            } catch (e) {
                console.error(`[${metadata.name}] Failed to log AccessibilityEvent: ${e}`);
            }

            return original_sendEvent.call(this, event);
        };

        send({ type: 'hook_loaded', hook: metadata.name, java: true });
        console.log(`[+] ${metadata.name} initialized`);
    } catch (e) {
        console.error(`[${metadata.name}] Initialization failed: ${e}`);
    }
});
