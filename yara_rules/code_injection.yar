rule Dynamic_Dex_Loading : dex dexclassloader dynamic_code code_injection
{
    meta:
        description = "Use of DexClassLoader and related API for runtime code loading or injection"
        category = "dex_loading"
        severity = "high"
        confidence = 90
        author = "apk-inspector"
        created = "2025-05-25"

    strings:
        // Core Java class used for dynamic code loading
        $class_loader = "dalvik.system.DexClassLoader"
        
        // Common method used to invoke loaded classes
        $invoke_class = "loadClass"
        
        // File extension associated with loaded .dex files
        $dex_extension = ".dex"
        
        // Optional: variants seen in malware
        $alt_loader = "dalvik.system.BaseDexClassLoader"
        $path_ref = "getDexPath"

    condition:
        // Trigger when core loader is present + one other indicator
        $class_loader and (1 of ($invoke_class, $dex_extension, $alt_loader, $path_ref))
}

rule Suspicious_Native_Invocation : native code_injection jni hooking
{
    meta:
        description = "Suspicious use of native loading and memory modification APIs indicating potential hooking or injection"
        category    = "native_injection"
        severity    = "high"
        confidence  = 90
        author      = "apk-inspector"
        created     = "2025-05-25"

    strings:
        // Core Java native-loading functions
        $load_lib1     = "System.loadLibrary"
        $load_lib2     = "System.load"

        // Known suspicious libraries
        $libhook       = "libhook.so"
        $libsubstrate  = "libsubstrate.so"

        // Native libc-level memory manipulation / loader API
        $dlopen        = "dlopen"
        $mprotect      = "mprotect"
        $dlsym         = "dlsym"

    condition:
        // Trigger if at least 2 indicators are present
        2 of ($load_lib*, $lib*, $dlopen, $mprotect, $dlsym)
}

rule Native_Library_Usage : jni native binary_integration
{
    meta:
        description = "Usage of native code via JNI or shared libraries"
        category = "binary_integration"
        severity = "medium"
        confidence = 75
        author = "apk-inspector"
        created = "2025-05-25"
    
    strings:
        $jni1 = "System.loadLibrary"
        $jni2 = "libnative-lib.so"
        $jni3 = "JNI_OnLoad"

    condition:
        any of them
}

