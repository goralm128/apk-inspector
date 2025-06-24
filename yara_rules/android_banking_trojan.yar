rule BankingTrojan_Overlay_Abuse : overlay phishing ui_banking {
    meta:
        description = "Banking trojan impersonating login UI via overlays or inflated phishing views"
        category    = "ui_phishing"
        severity    = "high"
        confidence  = "90"
        author      = "apk-inspector"
        created     = "2025-06-24"

    strings:
        $perm1     = "android.permission.SYSTEM_ALERT_WINDOW" nocase ascii
        $overlay   = "TYPE_APPLICATION_OVERLAY" nocase ascii
        $inflater  = "LayoutInflater.from" ascii
        $prompt1   = "Enter your password" nocase ascii
        $prompt2   = "Google Account Login" nocase ascii
        $bank_ui   = "Bank Login" nocase ascii

    condition:
        2 of ($overlay, $inflater, $prompt1, $prompt2, $bank_ui) and $perm1
}

rule BankingTrojan_Accessibility_Control : accessibility hijack automation {
    meta:
        description = "Banking trojan using Accessibility Service to automate UI and harvest screen content"
        category    = "accessibility_abuse"
        severity    = "critical"
        confidence  = "95"
        author      = "apk-inspector"
        created     = "2025-06-24"

    strings:
        $perm      = "android.permission.BIND_ACCESSIBILITY_SERVICE" nocase ascii
        $node      = "AccessibilityNodeInfo" nocase ascii
        $action1   = "performGlobalAction" nocase ascii
        $action2   = "performAction" nocase ascii
        $extract   = "getText()" nocase ascii
        $select    = "TYPE_VIEW_TEXT_SELECTION_CHANGED" nocase ascii

    condition:
        2 of ($action1, $action2, $extract, $select) and any of ($perm, $node)
}

rule BankingTrojan_SMS_OTP_Theft : sms otp intercept {
    meta:
        description = "Banking trojan intercepting SMS OTPs"
        category    = "otp_interception"
        severity    = "high"
        confidence  = "90"
        author      = "apk-inspector"
        created     = "2025-06-24"

    strings:
        $perm1   = "android.permission.RECEIVE_SMS" nocase ascii
        $perm2   = "android.permission.READ_SMS" nocase ascii
        $sms1    = "SMSRetriever" nocase ascii
        $otp_key = "Your OTP is" nocase ascii
        $otp_api = "/otp" nocase ascii

    condition:
        any of ($perm1, $perm2) and 1 of ($otp_key, $sms1, $otp_api)
}

rule BankingTrojan_Targeted_Package_Monitoring : app_hijack watchbank {
    meta:
        description = "Banking trojan monitoring installed packages to hijack legitimate bank UIs"
        category    = "bank_targeting"
        severity    = "high"
        confidence  = "85"
        author      = "apk-inspector"
        created     = "2025-06-24"

    strings:
        $intent1 = "android.intent.action.PACKAGE_ADDED" ascii
        $intent2 = "android.intent.action.PACKAGE_REPLACED" ascii
        $api     = "getInstalledPackages" ascii
        $b1      = "com.bankofamerica.android" ascii
        $b2      = "com.wf.wellsfargomobile" ascii
        $b3      = "com.chase.sig.android" ascii

    condition:
        1 of ($b1, $b2, $b3) and any of ($intent1, $intent2, $api)
}

rule BankingTrojan_C2_Communication : c2 telegram firebase {
    meta:
        description = "C2 communication via known APIs or backend panels"
        category    = "c2_exfiltration"
        severity    = "high"
        confidence  = "85"
        author      = "apk-inspector"
        created     = "2025-06-24"

    strings:
        $tele  = "api.telegram.org" ascii
        $fire  = ".firebaseio.com" ascii
        $gate  = "gate.php" ascii
        $panel = "/panel/" ascii

    condition:
        any of them
}

rule BankingTrojan_Obfuscated_Loader : obfuscation dropper dynamic_dex {
    meta:
        description = "Possible obfuscated loader using reflection and hidden DEX drops"
        category    = "dropper_behavior"
        severity    = "high"
        confidence  = "90"
        author      = "apk-inspector"
        created     = "2025-06-24"

    strings:
        $ref1    = "Class.forName" nocase ascii
        $ref2    = "loadClass" nocase ascii
        $dex1    = "payload.dex" ascii
        $decode  = "Base64.decode" nocase ascii

    condition:
        2 of ($ref1, $ref2, $dex1, $decode)
}