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
        $forname         = "java.lang.Class.forName" ascii nocase
        $getmethod       = "getMethod" ascii nocase
        $getdeclared     = "getDeclaredMethod" ascii nocase
        $invoke          = "invoke" ascii nocase
        $method_class    = "java.lang.reflect.Method" ascii nocase
        $constructor     = "java.lang.reflect.Constructor" ascii nocase
        $setaccessible   = "setAccessible" ascii nocase
        $getconstructor  = "getDeclaredConstructor" ascii nocase

    condition:
        2 of them
}
