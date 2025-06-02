'use strict';

/**
 * Hook Metadata
 */
const metadata = {
    name: "hook_accessibility_service",
    description: "Detects usage of AccessibilityService and related APIs",
    tags: ["accessibility", "uiautomation", "abuse"],
    sensitive: true
};

const logAccessibility = createHookLogger({
    hook: "AccessibilityService",
    category: "accessibility_abuse",
    tags: metadata.tags,
    description: metadata.description,
    sensitive: metadata.sensitive
});

Java.perform(() => {
    try {
        const AccService = Java.use("android.accessibilityservice.AccessibilityService");

        // Detect when service is started
        AccService.onServiceConnected.implementation = function () {
            logAccessibility({
                action: "onServiceConnected",
                class: this.$className,
                component: this.getComponentName().toString()
            });
            return this.onServiceConnected();
        };

        const NodeInfo = Java.use("android.view.accessibility.AccessibilityNodeInfo");

        // Dangerous calls
        NodeInfo.performAction.overload('int').implementation = function (action) {
            logAccessibility({
                action: "performAction",
                node: this.toString(),
                action_id: action
            });
            return this.performAction(action);
        };

    } catch (e) {
        console.error("[!] Failed to hook AccessibilityService:", e);
    }
});
