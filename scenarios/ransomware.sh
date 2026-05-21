#!/usr/bin/env bash
# Ransomware File Encryption Behavior Simulation
# MITRE ATT&CK: T1486 - Data Encrypted for Impact
# Tactic: Impact
# Severity: CRITICAL

SCENARIO_NAME="ransomware"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="CRITICAL"
SCENARIO_TACTIC="Impact"
SCENARIO_TECHNIQUE="T1486"

TIMESTAMP=$(date +%s)
DETECT_ID="cs-${TIMESTAMP}"

build_payload() {
    local tenant_id="${1:-default-tenant}"
    cat <<EOF
{
    "detect_id": "${DETECT_ID}",
    "customer_id": "${tenant_id}",
    "timestamp": ${TIMESTAMP},
    "sensor": {
        "hostname": "win-fileserver-02"
    },
    "process": {
        "user_name": "CORP\\\\svc_backup",
        "file_name": "encryptor.exe",
        "command_line": "encryptor.exe --target C:\\\\Data --extensions .docx,.xlsx,.pdf,.pst --ransom-note README.txt",
        "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
