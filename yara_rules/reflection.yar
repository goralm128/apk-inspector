rule Reflection_Usage : reflection evasion obfuscation
{
    meta:
        description = "Suspicious use of reflection APIs to evade static analysis"
        category = "reflection"
        severity = "medium"
        confidence = 80
        author = "apk-inspector"
        created = "2025-05-26"

    strings:
        $1 = "java.lang.Class.forName"
        $2 = "getMethod"
        $3 = "invoke"
        $4 = "java.lang.reflect.Method"
        $5 = "java.lang.reflect.Constructor"

    condition:
        2 of them
}
