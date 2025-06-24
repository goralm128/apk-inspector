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
        $ref1 = "Class.forName" ascii nocase
        $ref2 = "getMethod" ascii nocase
        $ref3 = "getDeclaredMethod" ascii nocase
        $ref4 = "setAccessible" ascii nocase
        $ref5 = "invoke" ascii nocase

    condition:
        3 of them
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
        $cls1 = /L[a-z]{1,2}\/[a-z]{1,2}\/[a-z]{1,2};/ ascii
        $cls2 = "a.a.a" ascii
        $cls3 = "b.b.b" ascii

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
        $xor1 = " ^ " ascii
        $xor2 = "char c = (char)(b ^ k);" ascii
        $xor3 = "deobfuscate(byte[] data, byte key)" ascii
        $xor4 = "data[i] ^ key" ascii
        $xor5 = "k = key[i % key.length]" ascii

    condition:
        2 of them
}
