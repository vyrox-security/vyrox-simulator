#!/usr/bin/env bash
# Mimikatz Credential Dumping Attack Simulation
# MITRE ATT&CK: T1003.001 - OS Credential Dumping: LSASS Memory
# Tactic: Credential Access
# Severity: CRITICAL

SCENARIO_NAME="mimikatz"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="CRITICAL"
SCENARIO_TACTIC="Credential Access"
SCENARIO_TECHNIQUE="T1003"

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
        "hostname": "win-desktop-01"
    },
    "process": {
        "user_name": "CORP\\\\jsmith",
        "file_name": "mimikatz.exe",
        "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        "sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
