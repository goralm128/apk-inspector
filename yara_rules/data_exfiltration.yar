rule Unencrypted_HTTP_Exfiltration : http exfiltration plaintext
{
    meta:
        description = "Unencrypted HTTP POST request or upload used in exfiltration"
        category = "network_exfiltration"
        severity = "high"
        confidence = 85
        author = "apk-inspector"
        created = "2025-05-25"

    strings:
        $post_api = "POST /api" nocase
        $post_send = "POST /sendData" nocase
        $php_endpoint = /http:\/\/[a-z0-9.-]+\/[a-z0-9._-]+\.(php|asp|jsp|exe)/

    condition:
        any of them
}

rule Suspicious_Exfil_Endpoints : c2 dropzone upload exfil
{
    meta:
        description = "Possible command and control or data drop endpoints"
        category = "network_exfiltration"
        severity = "medium"
        confidence = 80
        author = "apk-inspector"
        created = "2025-05-25"

    strings:
        $c2_1 = "command-and-control" nocase
        $c2_2 = "upload.php"
        $c2_3 = "botnet" nocase
        $c2_4 = "gate.php"

    condition:
        any of them
}

rule Suspicious_Exfil_Filenames : exfil file dump
{
    meta:
        description = "Filenames often associated with exfiltrated data"
        category = "network_exfiltration"
        severity = "medium"
        confidence = 75
        author = "apk-inspector"
        created = "2025-05-25"

    strings:
        $file1 = "dump.zip"
        $file2 = "logs.txt"
        $file3 = "data_payload.json"

    condition:
        any of them
}

rule Known_Bad_Hostnames : dns c2 dropzone
{
    meta:
        description = "Connections to known suspicious or malicious hostnames"
        category = "network_exfiltration"
        severity = "high"
        confidence = 90
        author = "apk-inspector"
        created = "2025-05-25"

    strings:
        $host1 = "maliciousdomain.com"
        $host2 = "cnc.example.org"
        $host3 = "dropzone.abc"

    condition:
        any of them
}

rule Hardcoded_IP_Addresses : ip_address network_exfiltration
{
    meta:
        description = "Suspicious hardcoded IP address patterns"
        category    = "network_exfiltration"
        severity    = "medium"
        confidence  = 75
        author      = "apk-inspector"
        created     = "2025-05-25"

    strings:
        $ip1 = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
        $ip2 = "http://" nocase
        $ip3 = "https://" nocase

    condition:
        $ip1 or any of ($ip2, $ip3)
}

