rule Overlay_Abuse : overlay ui_hijack phishing system_alert
{
    meta:
        description = "Abuse of SYSTEM_ALERT_WINDOW or runtime overlay behavior"
        category = "overlay_abuse"
        severity = "high"
        confidence = 90
        author = "apk-inspector"
        created = "2025-05-25"

    strings:
        $perm = "android.permission.SYSTEM_ALERT_WINDOW"
        $type_overlay = "TYPE_APPLICATION_OVERLAY"
        $type_alert = "TYPE_SYSTEM_ALERT"
        $layout = "WindowManager.LayoutParams"
        $view = "addView"

    condition:
        any of them
}

rule Accessibility_Service_Abuse : accessibility abuse automation clickjacking
{
    meta:
        description = "Detects abuse of Accessibility Service APIs often used in clickjacking or automated interaction"
        category = "accessibility_abuse"
        severity = "high"
        confidence = 90
        author = "apk-inspector"
        created = "2025-05-25"

    strings:
        // Manifest permission
        $perm = "android.permission.BIND_ACCESSIBILITY_SERVICE"
        
        // Class or interface
        $iface = "android.accessibilityservice.AccessibilityService"
        $impl  = "AccessibilityService"

        // Events and methods commonly abused
        $event = "TYPE_VIEW_CLICKED"
        $action1 = "performGlobalAction"
        $action2 = "TYPE_VIEW_FOCUSED"
        $action3 = "TYPE_VIEW_TEXT_CHANGED"
        $action4 = "TYPE_WINDOW_CONTENT_CHANGED"

    condition:
        // Detects at least 2 behavioral indicators + permission or service mention
        (
            2 of ($event, $action1, $action2, $action3, $action4)
        and
            any of ($perm, $iface, $impl)
        )
}

