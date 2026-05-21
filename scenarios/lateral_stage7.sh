#!/usr/bin/env bash
# Lateral Movement to Data Exfiltration - Stage 7: Collection
# MITRE ATT&CK: T1560 - Archive Collected Data
# Tactic: Collection
# Severity: HIGH

SCENARIO_NAME="lateral_to_exfil"
SCENARIO_STAGE=7
SCENARIO_STAGE_NAME="Collection"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="HIGH"
SCENARIO_TACTIC="Collection"
SCENARIO_TECHNIQUE="T1560"

TIMESTAMP=$(date +%s)
DETECT_ID="cs-stage7-${TIMESTAMP}"

build_payload() {
    local tenant_id="${1:-default-tenant}"
    cat <<EOF
{
    "detect_id": "${DETECT_ID}",
    "customer_id": "${tenant_id}",
    "timestamp": ${TIMESTAMP},
    "sensor": {
        "hostname": "fileserver-01"
    },
    "process": {
        "user_name": "CORP\\\\attacker",
        "file_name": "7z.exe",
        "command_line": "7z a -psecret C:\\\\temp\\\\backup.zip C:\\\\Finance\\\\2024\\\\*.xlsx",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000007"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
