#!/usr/bin/env bash
# =============================================================================
# Scenario: Benign Activity — Scheduled Backup Job
# =============================================================================
# MITRE ATT&CK: T1059 — Command and Scripting Interpreter
# Tactic:     Execution
# Severity:   LOW
#
# What this simulates:
#   A legitimate scheduled backup job using robocopy to copy user data
#   to a network share. This SHOULD be classified as BENIGN by the triage
#   pipeline — it's a false positive that tests whether Vyrox can
#   distinguish between malicious and benign activity.
#
# Detection signals:
#   - Process name: robocopy.exe (legitimate Windows backup tool)
#   - Command line: standard robocopy flags (/MIR, /R:3, /W:5, /LOG)
#   - User: svc_backup (service account, not a human user)
#
# Expected triage: BENIGN or LOW verdict. If this triggers HIGH or CRITICAL,
# your heuristics engine has a false positive problem. This scenario is
# specifically designed to test that.
# =============================================================================

SCENARIO_NAME="benign"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="LOW"
SCENARIO_TACTIC="Execution"
SCENARIO_TECHNIQUE="T1059"

TIMESTAMP=$(date +%s)
DETECT_ID="cs-${TIMESTAMP}"

# build_payload — Generate the CrowdStrike-format benign activity payload.
# Args: $1: tenant_id (default: "default-tenant")
build_payload() {
    local tenant_id="${1:-default-tenant}"
    cat <<EOF
{
    "detect_id": "${DETECT_ID}",
    "customer_id": "${tenant_id}",
    "timestamp": ${TIMESTAMP},
    "sensor": {
        "hostname": "win-workstation-10"
    },
    "process": {
        "user_name": "CORP\\\\svc_backup",
        "file_name": "robocopy.exe",
        "command_line": "robocopy C:\\\\Users \\\\nas01\\\\backups\\\\users /MIR /R:3 /W:5 /LOG:C:\\\\logs\\\\backup.log",
        "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
