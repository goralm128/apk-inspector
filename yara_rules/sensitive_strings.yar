rule Suspicious_Token_String : token api auth sensitive
{
    meta:
        description = "Hardcoded token or API key pattern (e.g., Bearer)"
        category    = "sensitive_string"
        severity    = "high"
        confidence  = 90
        author      = "apk-inspector"
        created     = "2025-05-25"

    strings:
        $token = /Bearer\s+[A-Za-z0-9._~+\/=-]{10,200}/ ascii nocase

    condition:
        $token
}

rule Hardcoded_JWT_Like_String : jwt token sensitive_string
{
    meta:
        description = "Possible hardcoded JWT token"
        category    = "sensitive_string"
        severity    = "high"
        confidence  = 85
        author      = "apk-inspector"
        created     = "2025-05-25"

    strings:
        $jwt1 = /[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}/ ascii
        $jwt2 = /eyJ[a-zA-Z0-9=._-]{20,}\.[a-zA-Z0-9=._-]{20,}\.[a-zA-Z0-9=._-]{20,}/ ascii

    condition:
        any of them
}

rule Suspicious_Encryption_Keys : sensitive_string crypto key iv
{
    meta:
        description = "Suspicious hardcoded encryption keys or IVs"
        category    = "sensitive_string"
        severity    = "high"
        confidence  = 80
        author      = "apk-inspector"
        created     = "2025-05-25"

    strings:
        $key1 = /key\s*=\s*["']/ nocase ascii
        $key2 = /aes\s*=\s*["']/ nocase ascii
        $key3 = /secret\s*=\s*["']/ nocase ascii
        $key4 = /encryption[_-]?key\s*[:=]\s*["']/ nocase ascii
        $iv1  = /iv\s*=\s*["']/ nocase ascii
        $iv2  = /nonce\s*=\s*["']/ nocase ascii

    condition:
        any of them
}
