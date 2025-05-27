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
        $token = /Bearer\s+[A-Za-z0-9._~+\/=-]+/

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
        $jwt = /[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}/

    condition:
        $jwt
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
        $key1 = "key = \"" nocase
        $key2 = "aes = \"" nocase
        $key3 = "secret = \"" nocase
        $iv1  = "iv = \"" nocase
        $iv2  = "nonce = \"" nocase

    condition:
        any of ($key*, $iv*)
}

