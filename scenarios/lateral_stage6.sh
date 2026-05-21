#!/usr/bin/env bash
# Lateral Movement to Data Exfiltration - Stage 6: Discovery
# MITRE ATT&CK: T1083 - File and Directory Discovery
# Tactic: Discovery
# Severity: MEDIUM

SCENARIO_NAME="lateral_to_exfil"
SCENARIO_STAGE=6
SCENARIO_STAGE_NAME="Discovery"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="MEDIUM"
SCENARIO_TACTIC="Discovery"
SCENARIO_TECHNIQUE="T1083"

TIMESTAMP=$(date +%s)
DETECT_ID="cs-stage6-${TIMESTAMP}"

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
        "file_name": "dir.exe",
        "command_line": "dir C:\\\\Finance\\\\2024\\\\*.xlsx",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000006"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
