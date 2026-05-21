#!/usr/bin/env bash
# SentinelOne Lateral Movement Simulation
# MITRE ATT&CK: T1021 - Remote Services
# Tactic: Lateral Movement
# Severity: HIGH

SCENARIO_NAME="sentinelone_lateral"
SCENARIO_SOURCE="sentinelone"
SCENARIO_SEVERITY="HIGH"
SCENARIO_TACTIC="Lateral Movement"
SCENARIO_TECHNIQUE="T1021"

TIMESTAMP=$(date +%s)
ALERT_ID="s1-${TIMESTAMP}"

build_payload() {
    local tenant_id="${1:-default-tenant}"
    cat <<EOF
{
    "id": "${ALERT_ID}",
    "accountId": "${tenant_id}",
    "createdAt": ${TIMESTAMP},
    "severity": "${SCENARIO_SEVERITY}",
    "agentRealtimeInfo": {
        "computerName": "win-workstation-05",
        "domain": "corp.local",
        "accountId": "${tenant_id}"
    },
    "processName": "psexec.exe",
    "commandLine": "psexec \\\\fileserver-01 -u CORP\\\\admin -p password cmd.exe",
    "fileFullName": "CORP\\\\admin",
    "fileContentHash": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    "mitreTactic": "${SCENARIO_TACTIC}",
    "mitreTechnique": "${SCENARIO_TECHNIQUE}"
}
EOF
}
