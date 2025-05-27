rule Suspicious_Reflection_Usage : reflection obfuscation dynamic_behavior
{
    meta:
        description = "Suspicious use of reflection APIs — often used for obfuscation or dynamic execution"
        category = "system_behavior"
        severity = "medium"
        confidence = 80
        author = "apk-inspector"
        created = "2025-05-25"

    strings:
        $ref1 = "Class.forName"
        $ref2 = "getMethod"
        $ref3 = "setAccessible"

    condition:
        all of ($ref1, $ref2, $ref3)
}

rule Obfuscated_Class_Name_Entropy : obfuscation entropy class_name string_obfuscation
{
    meta:
        description = "Suspicious class names using short or random identifiers that suggest obfuscation"
        category = "system_behavior"
        severity = "medium"
        confidence = 75
        author = "apk-inspector"
        created = "2025-05-25"

    strings:
        $cls1 = /L[a-z]{1,2}\/[a-z]{1,2}\/[a-z]{1,2};/
        $cls2 = "a.a.a"

    condition:
        any of them
}

rule XOR_Obfuscation_Pattern : obfuscation crypto_usage xor_pattern
{
    meta:
        description = "Suspicious XOR operation often used in custom obfuscation"
        category = "crypto_usage"
        severity = "medium"
        confidence = 70
        author = "apk-inspector"
        created = "2025-05-25"

    strings:
        $xor_a = " ^ "
        $xor_b = "char c = (char)(b ^ k);"
        $xor_c = "deobfuscate(byte[] data, byte key)"

    condition:
        2 of ($xor_a, $xor_b, $xor_c)
}


