
HOOK_CATEGORY_MAP = {
    # Network
    "send": "network",
    "recv": "network",
    "connect": "network",
    "Socket.connect": "network",
    "URLConnection.connect": "network",

    # Filesystem
    "open": "filesystem",
    "read": "filesystem",
    "write": "filesystem",
    "FileInputStream": "filesystem",
    "FileOutputStream": "filesystem",

    # Cryptography
    "Cipher.getInstance": "crypto_usage",
    "MessageDigest.getInstance": "crypto_usage",
    "KeyGenerator.getInstance": "crypto_usage",
    "Signature.getInstance": "crypto_usage",

    # Reflection
    "Class.forName": "reflection",
    "Method.invoke": "reflection",
    "Field.get": "reflection",

    #  Native code
    "System.loadLibrary": "native_injection",
    "System.load": "native_injection",
    "dlopen": "native_injection",

    # Accessibility abuse
    "AccessibilityService": "accessibility_abuse",
    "AccessibilityNodeInfo.performAction": "accessibility_abuse"
}
