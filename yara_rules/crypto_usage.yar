rule Generic_Crypto_API_Usage : crypto crypto_usage
{
    meta:
        description = "Use of standard Java cryptographic APIs (Cipher, KeyGenerator, KeySpec)"
        category = "crypto_usage"
        severity = "low"
        confidence = 60
        author = "apk-inspector"
        created = "2025-05-25"

    strings:
        $cipher   = "javax.crypto.Cipher" ascii nocase
        $keygen   = "KeyGenerator" ascii nocase
        $keyspec  = "SecretKeySpec" ascii nocase
        $mac      = "javax.crypto.Mac" ascii nocase
        $ivspec   = "IvParameterSpec" ascii nocase

    condition:
        any of them
}

rule Weak_Crypto_Primitives_Usage : crypto crypto_usage weak_crypto
{
    meta:
        description = "Use of weak or insecure cryptographic algorithms or patterns (e.g., AES/ECB, DES)"
        category = "crypto_usage"
        severity = "high"
        confidence = 90
        author = "apk-inspector"
        created = "2025-05-25"

    strings:
        $aes_ecb1 = "AES/ECB/PKCS5Padding" ascii
        $aes_ecb2 = "AES/ECB/NoPadding" ascii
        $des      = "DES" ascii
        $rc4      = "RC4" ascii
        $md5      = "MD5" ascii
        $hardcoded1 = "aes_key" ascii
        $xor_key  = "xor_key" ascii

    condition:
        any of them
}

rule Base64_Misuse_Indicator : crypto crypto_usage encoding obfuscation
{
    meta:
        description = "Base64 encoding detected; often used in obfuscation or key storage"
        category = "crypto_usage"
        severity = "low"
        confidence = 50
        author = "apk-inspector"
        created = "2025-05-25"

    strings:
        $encode  = "Base64.encode" ascii nocase
        $decode  = "Base64.decode" ascii nocase
        $variant = "android.util.Base64" ascii nocase
        $altlib  = "org.apache.commons.codec.binary.Base64" ascii nocase

    condition:
        any of them
}

rule Short_Key_Usage : crypto crypto_usage weak_crypto
{
    meta:
        description = "Possible use of short or weak cryptographic keys"
        category = "crypto_usage"
        severity = "high"
        confidence = 85
        author = "apk-inspector"
        created = "2025-05-25"

    strings:
        $key8  = "12345678" ascii
        $key16 = "1234567890abcdef" ascii
        $key64 = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh" ascii

    condition:
        any of them
}
