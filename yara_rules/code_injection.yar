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
        $class_loader     = "dalvik.system.DexClassLoader" ascii nocase
        $base_loader      = "dalvik.system.BaseDexClassLoader" ascii nocase
        $path_loader      = "dalvik.system.PathClassLoader" ascii nocase
        $load_class       = "loadClass" ascii nocase
        $dex_ext          = ".dex" ascii nocase
        $get_dex_path     = "getDexPath" ascii nocase
        $reflect_invoke   = "java.lang.reflect.Method.invoke" ascii nocase

    condition:
        // Require core loader and any other behavioral indicator
        any of ($class_loader, $base_loader, $path_loader) and
        1 of ($load_class, $dex_ext, $get_dex_path, $reflect_invoke)
}

rule Suspicious_Native_Invocation : native code_injection jni hooking
{
    meta:
        description = "Suspicious use of native loading and memory modification APIs indicating potential hooking or injection"
        category = "native_injection"
        severity = "high"
        confidence = 90
        author = "apk-inspector"
        created = "2025-05-25"

    strings:
        $load_lib1     = "System.loadLibrary" ascii nocase
        $load_lib2     = "System.load" ascii nocase
        $load_lib3     = "java.lang.Runtime.loadLibrary" ascii nocase
        $hook_lib      = "libhook.so" ascii
        $substrate_lib = "libsubstrate.so" ascii
        $dlopen        = "dlopen" ascii
        $mprotect      = "mprotect" ascii
        $dlsym         = "dlsym" ascii

    condition:
        // Trigger if 2 or more indicators hit (avoids noisy matches)
        2 of ($load_lib1, $load_lib2, $load_lib3, $hook_lib, $substrate_lib, $dlopen, $mprotect, $dlsym)
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
        $jni1     = "System.loadLibrary" ascii nocase
        $jni2     = "System.load" ascii nocase
        $jni3     = "JNI_OnLoad" ascii
        $lib_file = /\.so/ ascii   // generic .so reference

    condition:
        any of them
}
