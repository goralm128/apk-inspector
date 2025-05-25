rule Hardcoded_Credentials
{
  strings:
    $user = "username="
    $pass = "password="
    $api  = "api_key="
  condition:
    any of them
}

rule Suspicious_Encryption_Keys
{
  strings:
    $aes = /AESKey=[a-zA-Z0-9+\/]{16,}/
    $rsa = /-----BEGIN RSA PRIVATE KEY-----/
  condition:
    any of them
}

rule Native_Library_Indicators
{
  strings:
    $libc = "libc.so"
    $dex  = "classes.dex"
    $jni  = "JNI_OnLoad"
  condition:
    any of them
}

rule Shellcode_Like_Payload
{
  strings:
    $x86 = { 90 90 90 90 90 } // NOP sled
    $arm = { 01 10 8F E2 11 FF 2F E1 } // ARM shellcode prologue
  condition:
    any of them
}

rule Code_Obfuscation_Pattern
{
  strings:
    $1 = "com.secure.unknown" nocase
    $2 = "loadLibrary" nocase
    $3 = "System.load" nocase
  condition:
    any of them
}

rule suspicious_token_string {
    meta:
        description = "Hardcoded token or API key found"
        severity = "high"
        category = "sensitive_string"
        confidence = 90
    strings:
        $token = /Bearer\s+[A-Za-z0-9\-._~+\/]+=*/
    condition:
        $token
}
