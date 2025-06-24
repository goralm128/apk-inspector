rule Auto_Clicker_Behavior : autoclick automation accessibility abuse
{
    meta:
        description = "Auto-clicker behavior using Accessibility APIs or UI automation"
        category    = "accessibility_abuse"
        severity    = "high"
        confidence  = 80
        author      = "apk-inspector"
        created     = "2025-05-26"

    strings:
        $perform_action = "performAction" ascii nocase
        $loop_click     = "while (true)" ascii
        $thread_sleep   = "Thread.sleep" ascii
        $global_action  = "performGlobalAction" ascii nocase
        $click_text     = "click()" ascii

    condition:
        2 of them
}

rule Fake_UI_Overlay : overlay phishing impersonation
{
    meta:
        description = "Impersonated UI overlay or fake system prompt (phishing pattern)"
        category    = "overlay_abuse"
        severity    = "high"
        confidence  = 85
        author      = "apk-inspector"
        created     = "2025-05-26"

    strings:
        $view_inflate   = "LayoutInflater.from" ascii
        $fake_google    = "com.fake.google" ascii nocase
        $login_string   = "Google Account Login" ascii nocase
        $prompt_pass    = "Enter your password" ascii nocase
        $update_fake    = "Critical Update Required" ascii nocase

    condition:
        2 of them
}

rule Ransomware_Lock_Screen_Pattern : ransomware lockscreen persistent_overlay
{
    meta:
        description = "Indicators of ransomware-style persistent lock screens"
        category    = "overlay_abuse"
        severity    = "critical"
        confidence  = 95
        author      = "apk-inspector"
        created     = "2025-05-26"

    strings:
        $lock_perm      = "android.permission.DISABLE_KEYGUARD" ascii
        $flag_show      = "FLAG_SHOW_WHEN_LOCKED" ascii nocase
        $fullscreen     = "FLAG_FULLSCREEN" ascii nocase
        $block_input    = "setFlags(WindowManager.LayoutParams" ascii nocase
        $threat_text    = "Your device has been locked" ascii nocase
        $payment_text   = "Pay to unlock" ascii nocase

    condition:
        2 of them
}
