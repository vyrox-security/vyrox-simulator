#!/usr/bin/env bash
# =============================================================================
# Scenario: SentinelOne Lateral Movement (PsExec)
# =============================================================================
# MITRE ATT&CK: T1021 — Remote Services
# Tactic:     Lateral Movement
# Severity:   HIGH
#
# What this simulates:
#   An attacker using PsExec to move laterally from a compromised workstation
#   to a file server. PsExec is a legitimate Sysinternals tool that's commonly
#   abused by attackers for remote command execution.
#
# Detection signals:
#   - Process name: psexec.exe (LOLBin — legitimate tool, suspicious use)
#   - Command line: contains credentials in plaintext (-u, -p flags)
#   - MITRE technique: T1021 (Remote Services)
#
# Note: This uses the SentinelOne payload format (different field names
# from CrowdStrike) to test the SentinelOne ingestion webhook.
# =============================================================================

SCENARIO_NAME="sentinelone_lateral"
SCENARIO_SOURCE="sentinelone"
SCENARIO_SEVERITY="HIGH"
SCENARIO_TACTIC="Lateral Movement"
SCENARIO_TECHNIQUE="T1021"

TIMESTAMP=$(date +%s)
ALERT_ID="s1-${TIMESTAMP}"

# build_payload — Generate the SentinelOne-format lateral movement payload.
# Uses SentinelOne's schema: agentRealtimeInfo, processName, commandLine,
# fileFullName, fileContentHash, mitreTactic, mitreTechnique.
# Args: $1: tenant_id (default: "default-tenant")
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
