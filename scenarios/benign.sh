#!/usr/bin/env bash
# Benign Activity - Scheduled Backup Job
# This should be classified as BENIGN by the triage pipeline
# Severity: LOW (vendor may flag it, but triage should dismiss)

SCENARIO_NAME="benign"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="LOW"
SCENARIO_TACTIC="Execution"
SCENARIO_TECHNIQUE="T1059"

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
