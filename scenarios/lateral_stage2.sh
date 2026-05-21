#!/usr/bin/env bash
# Lateral Movement to Data Exfiltration - Stage 2: Execution
# MITRE ATT&CK: T1059 - Command and Scripting Interpreter
# Tactic: Execution
# Severity: CRITICAL

SCENARIO_NAME="lateral_to_exfil"
SCENARIO_STAGE=2
SCENARIO_STAGE_NAME="Execution"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="CRITICAL"
SCENARIO_TACTIC="Execution"
SCENARIO_TECHNIQUE="T1059"

TIMESTAMP=$(date +%s)
DETECT_ID="cs-stage2-${TIMESTAMP}"

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
        "file_name": "payload.exe",
        "command_line": "payload.exe -hidden -encoded JABjAGwA...",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000002"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
