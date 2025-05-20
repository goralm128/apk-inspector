rule AWS_Keys
{
  strings:
    $access_key = /AKIA[0-9A-Z]{16}/
    $secret_key = /[a-zA-Z0-9\/+=]{40}/
  condition:
    $access_key and $secret_key
}

rule Firebase_Leak
{
  strings:
    $url = /https?:\/\/[a-z0-9\-]+\.firebaseio\.com/
  condition:
    $url
}

rule JWT_Token
{
  strings:
    $jwt = /[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}/
  condition:
    $jwt
}

rule Hardcoded_IP
{
  strings:
    $ip = /((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/
  condition:
    $ip
}

rule Suspicious_Exported_Activity
{
  strings:
    $exported = "<activity android:exported=\"true\""
    $intent = "android.intent.action.SEND"
  condition:
    $exported and $intent
}

rule Base64_Secrets
{
  strings:
    $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/
  condition:
    $b64
}
