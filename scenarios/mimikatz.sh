#!/usr/bin/env bash
# =============================================================================
# Scenario: Mimikatz Credential Dumping
# =============================================================================
# MITRE ATT&CK: T1003.001 — OS Credential Dumping: LSASS Memory
# Tactic:     Credential Access
# Severity:   CRITICAL
#
# What this simulates:
#   An attacker running mimikatz.exe with the sekurlsa::logonpasswords
#   command to dump plaintext credentials from LSASS memory. This is
#   one of the most well-known post-exploitation techniques and should
#   trigger Vyrox's heuristics engine with high confidence.
#
# Detection signals:
#   - Process name: mimikatz.exe (dead giveaway)
#   - Command line: contains "sekurlsa::logonpasswords" (specific to cred dump)
#   - MITRE technique: T1003 (OS Credential Dumping)
#
# Expected triage: CRITICAL verdict, high confidence, no LLM needed.
# If this doesn't trigger CRITICAL, your heuristics engine is broken.
# =============================================================================

SCENARIO_NAME="mimikatz"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="CRITICAL"
SCENARIO_TACTIC="Credential Access"
SCENARIO_TECHNIQUE="T1003"

TIMESTAMP=$(date +%s)
DETECT_ID="cs-${TIMESTAMP}"

# build_payload — Generate the CrowdStrike-format alert payload.
#
# This function produces a JSON payload that mimics what CrowdStrike Falcon
# would send for a mimikatz detection. The structure matches the real
# webhook schema: sensor.hostname, process.user_name/file_name/command_line/sha256.
#
# Args:
#   $1: tenant_id — Multi-tenant isolation key (default: "default-tenant")
#
# Output:
#   JSON payload to stdout
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
