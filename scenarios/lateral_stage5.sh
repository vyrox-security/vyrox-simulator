#!/usr/bin/env bash
# Lateral Movement to Data Exfiltration - Stage 5: Lateral Movement
# MITRE ATT&CK: T1021 - Remote Services
# Tactic: Lateral Movement
# Severity: HIGH

SCENARIO_NAME="lateral_to_exfil"
SCENARIO_STAGE=5
SCENARIO_STAGE_NAME="Lateral Movement"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="HIGH"
SCENARIO_TACTIC="Lateral Movement"
SCENARIO_TECHNIQUE="T1021"

TIMESTAMP=$(date +%s)
DETECT_ID="cs-stage5-${TIMESTAMP}"

build_payload() {
    local tenant_id="${1:-default-tenant}"
    cat <<EOF
{
    "detect_id": "${DETECT_ID}",
    "customer_id": "${tenant_id}",
    "timestamp": ${TIMESTAMP},
    "sensor": {
        "hostname": "win-workstation-01"
    },
    "process": {
        "user_name": "CORP\\\\attacker",
        "file_name": "wmiprvse.exe",
        "command_line": "wmic /node:fileserver-01 process call create \"powershell -enc ...\"",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000005"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
