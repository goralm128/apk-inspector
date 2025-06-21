'use strict';

maybeRunJavaHook(async () => {
  const metadata = {
    name: "hook_accessibility_service",
    category: "accessibility",
    description: "Hooks AccessibilityService events and gesture dispatches",
    tags: ["java", "accessibility", "input", "overlay"],
    sensitive: true,
    entrypoint: "java"
  };

  const log = await waitForLogger(metadata);

  const AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");

  AccessibilityService.onAccessibilityEvent.implementation = function (event) {
    try {
      const summary = event?.toString?.() || "<unknown>";
      log(buildEvent({
        metadata,
        action: "onAccessibilityEvent",
        context: { stack: get_java_stack() },
        args: { summary: summary.slice(0, 200) }
      }));
    } catch (err) {
      console.error(`[${metadata.name}] Error in onAccessibilityEvent: ${err}`);
    }
    return this.onAccessibilityEvent(event);
  };

  AccessibilityService.dispatchGesture.overload(
    "android.accessibilityservice.GestureDescription",
    "android.accessibilityservice.AccessibilityService$GestureResultCallback",
    "android.os.Handler"
  ).implementation = function (gesture, callback, handler) {
    try {
      log(buildEvent({
        metadata,
        action: "dispatchGesture",
        context: { stack: get_java_stack() },
        args: { gesture: gesture?.toString?.() || "<unknown>" }
      }));
    } catch (err) {
      console.error(`[${metadata.name}] Error in dispatchGesture: ${err}`);
    }
    return this.dispatchGesture(gesture, callback, handler);
  };

  log(buildEvent({ metadata, action: "hook_loaded" }));
  send({ type: 'hook_loaded', hook: metadata.name });
  console.log(`[+] ${metadata.name} initialized`);
}, {
  name: "hook_accessibility_service",
  entrypoint: "java"
});
