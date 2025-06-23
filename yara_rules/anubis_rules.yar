rule Android_Malware_Anubis_Pandemidestek_Static
{
    meta:
        description = "Detects Anubis-pandemidestek APK via strings, permissions, and smali-based code"
        author = "Arcanum Cyber Bot"
        family = "Anubis"
        type = "Android Malware"
        date = "2025-06-23"
        confidence = "high"
        tags = "anubis, accessibility, overlay, exec"

    strings:
        // Smali class indicators
        $cls1 = "Landroid/accessibilityservice/AccessibilityService;" ascii
        $cls2 = "onAccessibilityEvent" ascii
        $cls3 = "TYPE_VIEW_CLICKED" ascii
        $cls4 = "TYPE_WINDOW_STATE_CHANGED" ascii
        $cls5 = "TYPE_VIEW_TEXT_CHANGED" ascii
        $cls6 = "AccessibilityEvent.TYPE_VIEW_FOCUSED" ascii

        // Permissions
        $perm1 = "android.permission.SYSTEM_ALERT_WINDOW" ascii
        $perm2 = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii
        $perm3 = "android.permission.PACKAGE_USAGE_STATS" ascii
        $perm4 = "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" ascii
        $perm5 = "android.permission.FOREGROUND_SERVICE" ascii

        // Obfuscated loader indicators
        $load1 = "android.content.ComponentName" ascii
        $load2 = "setComponentEnabledSetting" ascii
        $load3 = "Runtime.getRuntime().exec" ascii
        $load4 = "Base64.decode" ascii
        $load5 = "DexClassLoader" ascii
        $load6 = /base64,(?:[A-Za-z0-9+/=]{40,})/ ascii

        // C2 Indicators
        $c2_1 = "gate.php" ascii
        $c2_2 = "185.100." ascii
        $c2_3 = "kullanıcı adı" wide
        $c2_4 = "şifre" wide
        $c2_5 = "musteri.hizmetleri" wide ascii
        $c2_6 = "POST /gate" ascii
        $c2_7 = /http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ascii

        // Obfuscated class name patterns
        $obs1 = /L[a-z]{1,2}\/[a-z]{1,2}\/[a-z]{1,2};/ ascii
        $obs2 = /class\s+[A-Za-z]{1,2}[A-Za-z0-9]{8,20}/ ascii

    condition:
        (3 of ($cls*) or 3 of ($perm*)) and (1 of ($c2*) or 2 of ($load*) or any of ($obs*))
}

rule Android_Malware_Permission_Abuse
{
    meta:
        description = "Flags APKs with dangerous Android permissions common in banking trojans"
        author = "Arcanum Cyber Bot"
        type = "Android Malware Heuristics"
        date = "2025-06-23"
        tags = "permissions, privilege, abuse"
        risk = "medium-high"

    strings:
        $m1 = "android.permission.SYSTEM_ALERT_WINDOW" ascii
        $m2 = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii
        $m3 = "android.permission.PACKAGE_USAGE_STATS" ascii
        $m4 = "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" ascii
        $m5 = "android.permission.RECEIVE_SMS" ascii
        $m6 = "android.permission.SEND_SMS" ascii
        $m7 = "android.permission.READ_SMS" ascii

    condition:
        4 of ($m*)
}

rule Android_Malware_Anubis_Smali_Classes
{
    meta:
        description = "Detects Anubis APKs by class/function naming patterns in smali"
        author = "Arcanum Cyber Bot"
        family = "Anubis"
        date = "2025-06-23"
        confidence = "moderate"
        tags = "anubis, smali, class, overlay"

    strings:
        $sc1 = "StartWhileActivity" ascii
        $sc2 = "InjectionService" ascii
        $sc3 = "FakeLoginActivity" ascii
        $sc4 = "PlayProtect" ascii nocase
        $sc5 = /class\s+.*(Overlay|Inject|StartWhile|Hijack)\w*/ ascii

    condition:
        2 of ($sc*) and filesize < 5MB
}

rule Android_Anubis_Turkish_C2_Lures
{
    meta:
        description = "Detects Turkish lure strings and C2 indicators in Anubis-pandemidestek variants"
        author = "Arcanum Cyber Bot"
        date = "2025-06-23"
        family = "Anubis"
        tags = "anubis, turkish, lure, phishing, c2"

    strings:
        $t1 = "Tebrikler!" wide
        $t2 = "Banka kampanyası" wide
        $t3 = "Ücretsiz internet" wide
        $t4 = "pandemi destek" wide
        $t5 = "Hesabınıza TL tanımlandı" wide
        $t6 = "Mobil kampanya" wide
        $url1 = "http://185.100." ascii
        $url2 = "/gate.php" ascii
        $url3 = "/api/sendToken" ascii
        $url4 = /\/gate\/login/ ascii

    condition:
        (2 of ($t*) and 1 of ($url*))
}
