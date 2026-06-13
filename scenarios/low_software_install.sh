#!/usr/bin/env bash
# =============================================================================
# Scenario: Benign - signed software deployment
# =============================================================================
# MITRE ATT&CK: T1059
# Tactic:     Execution
# Severity:   LOW (vendor-reported; Vyrox re-triages independently)
#
# An unattended install of a signed package from the software share by the deploy service account.
#
# Expected Vyrox verdict: BENIGN/LOW.
# =============================================================================

SCENARIO_NAME="low_software_install"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="LOW"
SCENARIO_TACTIC="Execution"
SCENARIO_TECHNIQUE="T1059"

# Unique per fire (timestamp + random): the pipeline dedupes on
# (tenant, source, raw_id), so a per-second id would collapse rapid back-to-back
# fires of the same scenario into one alert. The random suffix keeps each fire a
# distinct detection, the way a real EDR assigns a fresh detect_id each time.
TIMESTAMP=$(date +%s)
DETECT_ID="cs-${TIMESTAMP}-${RANDOM}${RANDOM}"

# build_payload - emit the CrowdStrike-format detection JSON for this scenario.
# Args: $1 tenant_id (default "default-tenant").
build_payload() {
    local tenant_id="${1:-default-tenant}"
    cat <<EOF
{
    "detect_id": "${DETECT_ID}",
    "customer_id": "${tenant_id}",
    "timestamp": ${TIMESTAMP},
    "sensor": {
        "hostname": "win-workstation-07"
    },
    "process": {
        "user_name": "CORP\\\\svc_deploy",
        "file_name": "msiexec.exe",
        "command_line": "msiexec /i \\\\nas01\\\\software\\\\7zip-x64.msi /quiet /norestart",
        "sha256": "2222222222222222222222222222222222222222222222222222222222222222"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
