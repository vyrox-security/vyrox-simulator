#!/usr/bin/env bash
# =============================================================================
# Scenario: Lateral Movement to Exfiltration — Stage 3: Persistence
# =============================================================================
# MITRE ATT&CK: T1053 — Scheduled Task/Job
# Tactic:     Persistence
# Severity:   HIGH
#
# What this simulates:
#   The attacker creates a scheduled task to maintain persistence across
#   reboots. The task runs a hidden PowerShell command daily at 09:00.
# =============================================================================
SCENARIO_NAME="lateral_to_exfil"
SCENARIO_STAGE=3
SCENARIO_STAGE_NAME="Persistence"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="HIGH"
SCENARIO_TACTIC="Persistence"
SCENARIO_TECHNIQUE="T1053"
TIMESTAMP=$(date +%s)
DETECT_ID="cs-stage3-${TIMESTAMP}"
build_payload() {
    local tenant_id="${1:-default-tenant}"
    cat <<EOF
{"detect_id":"${DETECT_ID}","customer_id":"${tenant_id}","timestamp":${TIMESTAMP},"sensor":{"hostname":"win-workstation-01"},"process":{"user_name":"CORP\\\\attacker","file_name":"schtasks.exe","command_line":"schtasks /create /tn \"Update\" /tr \"powershell -w hidden -enc ...\" /sc daily /st 09:00","sha256":"0000000000000000000000000000000000000000000000000000000000000003"},"tactic":"${SCENARIO_TACTIC}","technique":"${SCENARIO_TECHNIQUE}","severity":"${SCENARIO_SEVERITY}"}
EOF
}
