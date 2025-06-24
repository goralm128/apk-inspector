rule AWS_Access_Key_ID : cloud aws key
{
    meta:
        description = "Possible hardcoded AWS Access Key ID"
        category    = "cloud_credential"
        severity    = "high"
        confidence  = 90
        author      = "apk-inspector"
        created     = "2025-05-25"

    strings:
        // AWS Access Key IDs usually start with AKIA or ASIA and are 20 chars long
        $akid1 = /AKIA[0-9A-Z]{16}/ ascii
        $akid2 = /ASIA[0-9A-Z]{16}/ ascii

    condition:
        any of them
}

rule GCP_Service_Account_JSON : cloud gcp json
{
    meta:
        description = "Possible hardcoded GCP Service Account credential in JSON"
        category    = "cloud_credential"
        severity    = "high"
        confidence  = 95
        author      = "apk-inspector"
        created     = "2025-05-25"

    strings:
        $gcp1 = "\"type\": \"service_account\"" ascii nocase
        $gcp2 = "\"private_key_id\": \"" ascii nocase
        $gcp3 = "\"client_email\": \"" ascii nocase

    condition:
        2 of them
}

rule OAuth_Client_Secrets : cloud oauth api
{
    meta:
        description = "Hardcoded OAuth client secret or ID"
        category    = "cloud_credential"
        severity    = "high"
        confidence  = 85
        author      = "apk-inspector"
        created     = "2025-05-25"

    strings:
        $cid   = /"client_id"\s*:\s*"[0-9]{12,32}-[a-z0-9.-]+\.apps\.googleusercontent\.com"/ ascii nocase
        $csec1 = /"client_secret"\s*:\s*"[A-Za-z0-9-_]{20,}/ ascii nocase
        $csec2 = /"consumer_secret"\s*:\s*"[A-Za-z0-9-_]{20,}/ ascii nocase

    condition:
        any of them
}
