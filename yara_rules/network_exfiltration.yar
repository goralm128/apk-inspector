rule Unencrypted_HTTP_Exfil
{
  strings:
    $http_post = "POST /api" nocase
    $http_send = "POST /sendData" nocase
    $plain_url = /http:\/\/[a-z0-9.-]+\/[a-z0-9._-]+\.(php|asp|jsp|exe)/
  condition:
    any of them
}

rule Suspicious_Endpoints
{
  strings:
    $1 = "command-and-control" nocase
    $2 = "upload.php"
    $3 = "botnet" nocase
    $4 = "gate.php"
  condition:
    any of them
}

rule Exfiltration_Filenames
{
  strings:
    $1 = "dump.zip"
    $2 = "logs.txt"
    $3 = "data_payload.json"
  condition:
    any of them
}

rule Known_Bad_Hostnames
{
  strings:
    $1 = "maliciousdomain.com"
    $2 = "cnc.example.org"
    $3 = "dropzone.abc"
  condition:
    any of them
}
