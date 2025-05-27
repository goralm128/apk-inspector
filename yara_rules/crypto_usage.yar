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
        $cipher = "javax.crypto.Cipher"
        $keygen = "KeyGenerator"
        $keyspec = "SecretKeySpec"

    condition:
        any of ($cipher, $keygen, $keyspec)
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
        $aes_ecb = "AES/ECB/PKCS5Padding"
        $des_alg = "DES"
        $hardcoded = "aes_key"
        $xor_key = "xor_key"

    condition:
        any of ($aes_ecb, $des_alg, $hardcoded, $xor_key)
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
        $encoder = "Base64.encode"
        $decoder = "Base64.decode"
        $variant = "android.util.Base64"

    condition:
        any of ($encoder, $decoder, $variant)
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
        $key8 = "12345678"
        $key16 = "1234567890abcdef"
        $key64 = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh"

    condition:
        any of ($key8, $key16, $key64)
}


